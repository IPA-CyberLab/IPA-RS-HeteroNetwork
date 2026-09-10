//! HTTP boundaries for opt-in quorum administration and owner-authenticated signing.
//! New-code instances without a local manifest fail closed after shared-anchor activation.
//! This cannot constrain old binaries, a rogue root, or the database owner.

mod rotation;
pub mod sudo;
pub(super) use rotation::{active_manifest, apply_rotation};
pub use rotation::{
    signer_router_with_rotation_anchor, RotationRound1Request, RotationRound2Request,
    MANIFEST_PATH, ROTATION_PATH,
};
pub use sudo::sudo_signer_router;

use axum::body::{to_bytes, Bytes};
use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum::{
    body::Body,
    extract::State,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ipars_control_plane::{AdminCapabilityUse, ControlPlane, ControlPlaneStore};
use ipars_quorum::{
    frost, CapabilityClaims, CapabilityToken, Manifest, RequestProof, SignerEngine,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::sync::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use super::{bearer_token_from_headers, AccessTokenValidation, ErrorResponse, WebUiAuthConfig};

const MAX_ADMIN_BODY_BYTES: usize = 1024 * 1024;
const MAX_SIGNER_BODY_BYTES: usize = 256 * 1024;
const MAX_QUORUM_HEADER_BYTES: usize = 64 * 1024;
const BODY_DEADLINE: Duration = Duration::from_secs(5);
const AUTH_DEADLINE: Duration = Duration::from_secs(10);
const MAX_SIGNER_IN_FLIGHT: usize = 16;
pub const REVOCATIONS_PATH: &str = "/v1/admin/quorum/revocations";

#[derive(Clone)]
struct VerifiedCapability(AdminCapabilityUse);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequest {
    pub request_id: String,
}

enum BoundaryError {
    InvalidRevocation,
    ClockUnavailable,
}

impl IntoResponse for BoundaryError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidRevocation => {
                rejected(StatusCode::BAD_REQUEST, "invalid quorum revocation request")
            }
            Self::ClockUnavailable => {
                rejected(StatusCode::SERVICE_UNAVAILABLE, "quorum clock unavailable")
            }
        }
    }
}

fn parse_revocation(bytes: &[u8]) -> Result<RevocationRequest, BoundaryError> {
    let mut value: RevocationRequest =
        serde_json::from_slice(bytes).map_err(|_| BoundaryError::InvalidRevocation)?;
    if value.request_id.len() != 64
        || !value
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(BoundaryError::InvalidRevocation);
    }
    value.request_id.make_ascii_lowercase();
    Ok(value)
}

struct SignerHttpAuth {
    owner: WebUiAuthConfig,
    capacity: Arc<Semaphore>,
}

impl SignerHttpAuth {
    fn new(owner: WebUiAuthConfig) -> Result<Self, String> {
        if owner.required_email.is_none() || owner.required_subject.is_none() {
            return Err(
                "quorum signer requires configured OIDC owner email and subject".to_string(),
            );
        }
        Ok(Self {
            owner,
            capacity: Arc::new(Semaphore::new(MAX_SIGNER_IN_FLIGHT)),
        })
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<OwnedSemaphorePermit, Response> {
        let permit = self.capacity.clone().try_acquire_owned().map_err(|_| {
            rejected(
                StatusCode::TOO_MANY_REQUESTS,
                "quorum signer capacity exhausted",
            )
        })?;
        require_owner(&self.owner, headers).await?;
        Ok(permit)
    }
}

/// Base64url (without padding) encoded JSON quorum capability.
pub const QUORUM_TOKEN_HEADER: &str = "x-heteronetwork-quorum-token";
/// Base64url (without padding) encoded JSON requester proof of possession.
pub const QUORUM_PROOF_HEADER: &str = "x-heteronetwork-quorum-proof";

type VerificationFuture = Pin<Box<dyn Future<Output = Result<Request, Response>> + Send>>;
pub(super) type AnchorProbe =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<bool, ()>> + Send>> + Send + Sync>;

pub(super) fn anchor_probe<S: ControlPlaneStore + 'static>(
    plane: Arc<ControlPlane<S>>,
) -> AnchorProbe {
    let capacity = Arc::new(Semaphore::new(16));
    Arc::new(move || {
        let plane = plane.clone();
        let capacity = capacity.clone();
        Box::pin(async move {
            let _permit = capacity.try_acquire_owned().map_err(|_| ())?;
            match timeout(
                Duration::from_secs(5),
                plane.get_admin_quorum_manifest_anchor(),
            )
            .await
            {
                Ok(Ok(anchor)) => Ok(anchor.is_some()),
                Ok(Err(_)) | Err(_) => Err(()),
            }
        })
    })
}

/// A trusted verifier coupled to the shared atomic replay/revocation ledger.
/// Construction binds cryptographic verification to a control plane's shared store.
pub struct QuorumVerifier {
    verify_and_consume: Arc<dyn Fn(Request) -> VerificationFuture + Send + Sync>,
}

impl QuorumVerifier {
    pub fn new<S: ControlPlaneStore + 'static>(
        manifest: Manifest,
        plane: Arc<ControlPlane<S>>,
    ) -> Result<Self, String> {
        manifest
            .validate()
            .map_err(|_| "invalid admin quorum manifest".to_string())?;
        if manifest.cluster_id != plane.config().cluster_id.as_str() {
            return Err("admin quorum manifest cluster mismatch".to_string());
        }
        let capacity = Arc::new(Semaphore::new(16));
        Ok(Self {
            verify_and_consume: Arc::new(move |request| {
                let plane = plane.clone();
                let capacity = capacity.clone();
                Box::pin(async move {
                    let _permit = capacity.try_acquire_owned().map_err(|_| {
                        rejected(
                            StatusCode::TOO_MANY_REQUESTS,
                            "quorum verifier capacity exhausted",
                        )
                    })?;
                    if request.uri().path() == ROTATION_PATH {
                        return rotation::authorize_rotation(plane.as_ref(), request).await;
                    }
                    let token: CapabilityToken =
                        decode_header(request.headers(), QUORUM_TOKEN_HEADER).ok_or_else(|| {
                            rejected(StatusCode::UNAUTHORIZED, "quorum capability required")
                        })?;
                    let proof: RequestProof = decode_header(request.headers(), QUORUM_PROOF_HEADER)
                        .ok_or_else(|| {
                            rejected(StatusCode::UNAUTHORIZED, "quorum requester proof required")
                        })?;
                    // Core capabilities allow exact raw paths only, never unsigned query parameters.
                    if request.uri().query().is_some() {
                        return Err(rejected(
                            StatusCode::UNAUTHORIZED,
                            "quorum request binding rejected",
                        ));
                    }
                    let (mut parts, bytes) = bounded_body(request, MAX_ADMIN_BODY_BYTES).await?;
                    let manifest = rotation::load_active(plane.as_ref()).await?;
                    if parts.uri.path() == REVOCATIONS_PATH {
                        parse_revocation(&bytes).map_err(IntoResponse::into_response)?;
                    }
                    let now = Utc::now();
                    let seconds = u64::try_from(now.timestamp()).map_err(|_| {
                        rejected(StatusCode::SERVICE_UNAVAILABLE, "quorum clock unavailable")
                    })?;
                    ipars_quorum::verify_capability(
                        &manifest,
                        &token,
                        &proof,
                        parts.method.as_str(),
                        parts.uri.path(),
                        &bytes,
                        seconds,
                    )
                    .map_err(|_| {
                        rejected(StatusCode::UNAUTHORIZED, "quorum authorization rejected")
                    })?;
                    let expires_at = i64::try_from(token.claims.expires_at)
                        .ok()
                        .and_then(|value| DateTime::from_timestamp(value, 0))
                        .ok_or_else(|| {
                            rejected(StatusCode::UNAUTHORIZED, "quorum authorization rejected")
                        })?;
                    let record = AdminCapabilityUse {
                        cluster_id: plane.config().cluster_id.clone(),
                        manifest_epoch: token.claims.epoch,
                        manifest_digest: token.claims.manifest_digest.clone(),
                        request_id: hex_bytes(&token.claims.request_id),
                        claims_digest: hex_bytes(&Sha256::digest(token.claims.signing_bytes())),
                        expires_at,
                        received_at: now,
                        method: parts.method.to_string(),
                        path: parts.uri.path().to_string(),
                        requester_public_key: hex_bytes(&token.claims.requester_public_key),
                    };
                    // A timeout may leave a committed tombstone. Never dispatch on an uncertain result.
                    match timeout(
                        Duration::from_secs(5),
                        plane.consume_admin_capability(record.clone()),
                    )
                    .await
                    {
                        Ok(Ok(true)) => {
                            parts.extensions.insert(VerifiedCapability(record));
                            Ok(Request::from_parts(parts, Body::from(bytes)))
                        }
                        Ok(Ok(false)) => Err(rejected(
                            StatusCode::UNAUTHORIZED,
                            "quorum capability unavailable",
                        )),
                        Ok(Err(_)) | Err(_) => Err(rejected(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "quorum authorization store unavailable",
                        )),
                    }
                })
            }),
        })
    }

    pub(super) async fn authorize(&self, request: Request) -> Result<Request, Response> {
        (self.verify_and_consume)(request).await
    }
}

pub(super) async fn revoke<S, L>(
    State(state): State<super::ControlPlaneHttpState<S, L>>,
    request: Request,
) -> Result<Response, Response>
where
    S: ControlPlaneStore + 'static,
    L: ipars_control_plane::TokenLedger + 'static,
{
    let approved = request
        .extensions()
        .get::<VerifiedCapability>()
        .cloned()
        .ok_or_else(|| rejected(StatusCode::UNAUTHORIZED, "quorum authorization required"))?;
    let (_, bytes) = bounded_body(request, MAX_ADMIN_BODY_BYTES).await?;
    let target = parse_revocation(&bytes).map_err(IntoResponse::into_response)?;
    let now = Utc::now();
    let record = ipars_control_plane::AdminCapabilityRevocation {
        cluster_id: approved.0.cluster_id,
        manifest_epoch: approved.0.manifest_epoch,
        manifest_digest: approved.0.manifest_digest,
        request_id: target.request_id,
        expires_at: now + chrono::Duration::seconds(ipars_quorum::MAX_CAPABILITY_TTL_SECS as i64),
        received_at: now,
        method: approved.0.method,
        path: approved.0.path,
        requester_public_key: approved.0.requester_public_key,
    };
    match timeout(
        Duration::from_secs(5),
        state.plane.revoke_admin_capability(record),
    )
    .await
    {
        Ok(Ok(revoked)) => Ok(Json(serde_json::json!({"revoked": revoked})).into_response()),
        Ok(Err(_)) | Err(_) => Err(rejected(
            StatusCode::SERVICE_UNAVAILABLE,
            "quorum authorization store unavailable",
        )),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Round1Request {
    pub claims: CapabilityClaims,
    pub proof: RequestProof,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Round2Request {
    pub session_id: [u8; 32],
    pub claims: CapabilityClaims,
    pub proof: RequestProof,
    pub signing_package: frost::SigningPackage,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Round2Response {
    pub signature_share: frost::round2::SignatureShare,
}

struct SignerState {
    auth: SignerHttpAuth,
    engine: Mutex<SignerEngine>,
}

/// Standalone router: the daemon must bind it only to a trusted VPN or loopback address.
/// Membership and key shares come exclusively from local trusted configuration.
/// Owner OIDC validation on each round is automatic approval, not independent human votes.
/// This application-level policy does not defend against a rogue root or database owner.
pub fn signer_router(
    manifest: Manifest,
    key_package: frost::keys::KeyPackage,
    node_id: impl AsRef<str>,
    auth: WebUiAuthConfig,
) -> Result<Router, String> {
    let auth = SignerHttpAuth::new(auth)?;
    let engine = SignerEngine::new(manifest, node_id.as_ref(), key_package, 128, 60)
        .map_err(|_| "invalid quorum signer configuration".to_string())?;
    let state = Arc::new(SignerState {
        auth,
        engine: Mutex::new(engine),
    });
    Ok(Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/v1/quorum/round1", post(round1))
        .route("/v1/quorum/round2", post(round2))
        .with_state(state))
}

fn current_seconds() -> Result<u64, BoundaryError> {
    u64::try_from(Utc::now().timestamp()).map_err(|_| BoundaryError::ClockUnavailable)
}

fn round_error(error: ipars_quorum::Error) -> Response {
    match error {
        ipars_quorum::Error::Capacity => rejected(
            StatusCode::TOO_MANY_REQUESTS,
            "quorum signer capacity exhausted",
        ),
        _ => rejected(StatusCode::BAD_REQUEST, "quorum signing request rejected"),
    }
}

async fn round1(
    State(state): State<Arc<SignerState>>,
    request: Request,
) -> Result<Response, Response> {
    let _permit = state.auth.authenticate(request.headers()).await?;
    let (_, bytes) = bounded_body(request, MAX_SIGNER_BODY_BYTES).await?;
    let request: Round1Request = serde_json::from_slice(&bytes)
        .map_err(|_| rejected(StatusCode::BAD_REQUEST, "invalid quorum signing request"))?;
    let mut engine = state
        .engine
        .try_lock()
        .map_err(|_| rejected(StatusCode::TOO_MANY_REQUESTS, "quorum signer busy"))?;
    let result = engine
        .round1(
            &request.claims,
            &request.proof,
            current_seconds().map_err(IntoResponse::into_response)?,
        )
        .map_err(round_error)?;
    Ok(Json(result).into_response())
}

async fn round2(
    State(state): State<Arc<SignerState>>,
    request: Request,
) -> Result<Response, Response> {
    let _permit = state.auth.authenticate(request.headers()).await?;
    let (_, bytes) = bounded_body(request, MAX_SIGNER_BODY_BYTES).await?;
    let request: Round2Request = serde_json::from_slice(&bytes)
        .map_err(|_| rejected(StatusCode::BAD_REQUEST, "invalid quorum signing request"))?;
    request.proof.verify(&request.claims).map_err(round_error)?;
    let mut engine = state
        .engine
        .try_lock()
        .map_err(|_| rejected(StatusCode::TOO_MANY_REQUESTS, "quorum signer busy"))?;
    let signature_share = engine
        .round2(
            request.session_id,
            &request.claims,
            &request.signing_package,
            current_seconds().map_err(IntoResponse::into_response)?,
        )
        .map_err(round_error)?;
    Ok(Json(Round2Response { signature_share }).into_response())
}

fn decode_header<T: DeserializeOwned>(headers: &HeaderMap, name: &'static str) -> Option<T> {
    let encoded = unique_header(headers, name)?;
    let decoded = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn rejected(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
        .into_response()
}

pub(super) fn mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || value.is_empty() || value.len() > MAX_QUORUM_HEADER_BYTES {
        return None;
    }
    Some(value)
}

async fn bounded_body(
    request: Request,
    limit: usize,
) -> Result<(axum::http::request::Parts, Bytes), Response> {
    let (parts, body) = request.into_parts();
    match timeout(BODY_DEADLINE, to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => Ok((parts, bytes)),
        Ok(Err(_)) => Err(rejected(
            StatusCode::PAYLOAD_TOO_LARGE,
            "quorum request body rejected",
        )),
        Err(_) => Err(rejected(
            StatusCode::REQUEST_TIMEOUT,
            "quorum request body timed out",
        )),
    }
}

async fn require_owner(auth: &WebUiAuthConfig, headers: &HeaderMap) -> Result<(), Response> {
    // Do not accept an operator token or cache a successful round-one identity.
    if auth.required_email.is_none()
        || auth.required_subject.is_none()
        || unique_header(headers, "authorization").is_none()
    {
        return Err(rejected(
            StatusCode::UNAUTHORIZED,
            "quorum signer owner authentication required",
        ));
    }
    let Some(token) = bearer_token_from_headers(headers) else {
        return Err(rejected(
            StatusCode::UNAUTHORIZED,
            "quorum signer owner authentication required",
        ));
    };
    match timeout(AUTH_DEADLINE, auth.access_token_validation(token)).await {
        Ok(AccessTokenValidation::Valid) => Ok(()),
        Ok(AccessTokenValidation::Invalid) => Err(rejected(
            StatusCode::UNAUTHORIZED,
            "quorum signer owner authentication rejected",
        )),
        Ok(AccessTokenValidation::Unavailable) | Err(_) => Err(rejected(
            StatusCode::SERVICE_UNAVAILABLE,
            "quorum signer identity provider unavailable",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, HeaderValue};
    use ed25519_dalek::{Signer, SigningKey};
    use ipars_control_plane::{ControlPlaneConfig, InMemoryStore};
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn sign_transition(
        group: &Manifest,
        keys: &[frost::keys::KeyPackage],
        old: &Manifest,
        transition: &ipars_quorum::ManifestTransition,
    ) -> TestResult<Vec<u8>> {
        let mut engines = keys
            .iter()
            .enumerate()
            .take(usize::from(group.threshold()))
            .map(|(i, key)| {
                SignerEngine::new(
                    group.clone(),
                    &format!("node-{}", i + 1),
                    key.clone(),
                    4,
                    60,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rounds = engines
            .iter_mut()
            .map(|engine| engine.round1_rotation(old, transition, transition.issued_at))
            .collect::<Result<Vec<_>, _>>()?;
        let commitments = rounds
            .iter()
            .map(|r| Ok((frost::Identifier::try_from(r.identifier)?, r.commitments)))
            .collect::<TestResult<BTreeMap<_, _>>>()?;
        let package = frost::SigningPackage::new(commitments, &transition.signing_bytes()?);
        let shares = engines
            .iter_mut()
            .zip(rounds)
            .map(|(engine, r)| {
                Ok((
                    frost::Identifier::try_from(r.identifier)?,
                    engine.round2_rotation(
                        r.session_id,
                        old,
                        transition,
                        &package,
                        transition.issued_at,
                    )?,
                ))
            })
            .collect::<TestResult<BTreeMap<_, _>>>()?;
        Ok(frost::aggregate(&package, &shares, &group.public_keys()?)?.serialize()?)
    }

    #[tokio::test]
    async fn rotation_http_requires_both_groups_and_cas_then_uses_active_epoch() -> TestResult {
        let (old, old_keys, _, _) = fixture()?;
        let (mut new, new_keys, mut claims, _) = fixture()?;
        new.epoch = old.epoch + 1;
        let transition = ipars_quorum::ManifestTransition {
            old_manifest_digest: old.digest()?,
            new_manifest: new.clone(),
            request_id: [42; 32],
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
        };
        let rotation = ipars_quorum::ManifestRotation {
            old_signature: sign_transition(&old, &old_keys, &old, &transition)?,
            new_signature: sign_transition(&new, &new_keys, &old, &transition)?,
            transition,
        };
        let plane = test_plane(Arc::new(InMemoryStore::default()))?;
        plane
            .bind_admin_quorum_manifest(old.epoch, &old.digest()?)
            .await?;
        plane.publish_admin_quorum_manifest(old.clone()).await?;
        let app = super::super::router(
            http_state(plane.clone()).with_admin_quorum_manifest(old.clone())?,
        );
        let send = |value: &ipars_quorum::ManifestRotation, path: &str| -> TestResult<Request> {
            Ok(Request::builder()
                .method(Method::POST)
                .uri(path)
                .header("authorization", "Bearer test-operator-token")
                .body(Body::from(serde_json::to_vec(value)?))?)
        };
        let mut invalid = rotation.clone();
        invalid.new_signature = invalid.old_signature.clone();
        assert_eq!(
            app.clone()
                .oneshot(send(&invalid, ROTATION_PATH)?)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        invalid = rotation.clone();
        invalid.old_signature = invalid.new_signature.clone();
        assert_eq!(
            app.clone()
                .oneshot(send(&invalid, ROTATION_PATH)?)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(send(&rotation, &format!("{ROTATION_PATH}?x=1"))?)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(send(&rotation, ROTATION_PATH)?)
                .await?
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            plane.get_active_admin_quorum_manifest().await?,
            Some(new.clone())
        );
        assert_ne!(
            app.clone()
                .oneshot(send(&rotation, ROTATION_PATH)?)
                .await?
                .status(),
            StatusCode::OK
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(MANIFEST_PATH)
                    .header("authorization", "Bearer test-operator-token")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let active: Manifest =
            serde_json::from_slice(&to_bytes(response.into_body(), MAX_ADMIN_BODY_BYTES).await?)?;
        assert_eq!(active, new);
        claims.epoch = new.epoch;
        claims.manifest_digest = new.digest()?;
        let requester = SigningKey::from_bytes(&[7; 32]);
        claims.requester_public_key = requester.verifying_key().to_bytes();
        let proof = RequestProof {
            signature: requester.sign(&claims.proof_bytes()).to_bytes().to_vec(),
        };
        // The existing verifier reads the new shared epoch without a router restart.
        let token = signed_token(&new, &new_keys, &claims, &proof)?;
        let verifier = QuorumVerifier::new(old, plane)?;
        let request = Request::builder()
            .method(&*claims.method)
            .uri(&claims.path)
            .header(
                QUORUM_TOKEN_HEADER,
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&token)?),
            )
            .header(
                QUORUM_PROOF_HEADER,
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&proof)?),
            )
            .body(Body::from(" { }\n"))?;
        assert!(verifier.authorize(request).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn rotation_http_unconfigured_operator_cannot_apply() -> TestResult {
        let plane = test_plane(Arc::new(InMemoryStore::default()))?;
        let app = super::super::router(http_state(plane));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(ROTATION_PATH)
                    .header("authorization", "Bearer test-operator-token")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(serde_json::from_value::<RotationRound1Request>(
            serde_json::json!({"old_manifest":{}})
        )
        .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn rotation_http_signer_pins_old_manifest_and_requires_owner_each_round() -> TestResult {
        let (old, keys, claims, _) = fixture()?;
        let (mut new, _, _, _) = fixture()?;
        new.epoch = old.epoch + 1;
        let transition = ipars_quorum::ManifestTransition {
            old_manifest_digest: old.digest()?,
            new_manifest: new,
            request_id: [43; 32],
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let provider = Router::new().route(
            "/realms/test/protocol/openid-connect/userinfo",
            get(|| async {
                Json(serde_json::json!({"sub":"owner", "email":"owner@example.test"}))
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, provider).await;
        });
        let auth = WebUiAuthConfig::new(
            super::super::WebAuthProvider::Keycloak,
            "https://issuer.example.test/realms/test".into(),
            "test-client".into(),
            None,
            Some(format!("http://{address}/realms/test")),
            "openid".into(),
        )?
        .with_required_email("owner@example.test".into())?
        .with_required_subject("owner".into())?;
        let app = signer_router_with_rotation_anchor(
            old.clone(),
            keys[0].clone(),
            "node-1",
            auth,
            old.clone(),
        )?;
        let request =
            |value: serde_json::Value, authorized: bool, round: u8| -> TestResult<Request> {
                let mut builder = Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/quorum/rotation/round{round}"));
                if authorized {
                    builder = builder.header("authorization", "Bearer owner-token");
                }
                Ok(builder.body(Body::from(serde_json::to_vec(&value)?))?)
            };
        let body = serde_json::to_value(RotationRound1Request {
            transition: transition.clone(),
        })?;
        assert_eq!(
            app.clone()
                .oneshot(request(body.clone(), false, 1)?)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let mut substituted = body.clone();
        substituted["old_manifest"] = serde_json::to_value(&old)?;
        assert_eq!(
            app.clone()
                .oneshot(request(substituted, true, 1)?)
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut wrong_anchor = body.clone();
        wrong_anchor["transition"]["old_manifest_digest"] = serde_json::json!("a".repeat(64));
        assert_eq!(
            app.clone()
                .oneshot(request(wrong_anchor, true, 1)?)
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        let response = app.clone().oneshot(request(body, true, 1)?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let first: ipars_quorum::Round1Response =
            serde_json::from_slice(&to_bytes(response.into_body(), MAX_SIGNER_BODY_BYTES).await?)?;
        let mut second_engine = SignerEngine::new(old.clone(), "node-2", keys[1].clone(), 4, 60)?;
        let second = second_engine.round1_rotation(&old, &transition, claims.issued_at)?;
        let package = frost::SigningPackage::new(
            BTreeMap::from([
                (
                    frost::Identifier::try_from(first.identifier)?,
                    first.commitments,
                ),
                (
                    frost::Identifier::try_from(second.identifier)?,
                    second.commitments,
                ),
            ]),
            &transition.signing_bytes()?,
        );
        let body = serde_json::to_value(RotationRound2Request {
            session_id: first.session_id,
            transition,
            signing_package: package,
        })?;
        assert_eq!(
            app.clone()
                .oneshot(request(body.clone(), false, 2)?)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(request(body.clone(), true, 2)?)
                .await?
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.oneshot(request(body, true, 2)?).await?.status(),
            StatusCode::BAD_REQUEST
        );
        server.abort();
        Ok(())
    }

    fn fixture() -> TestResult<(
        Manifest,
        Vec<frost::keys::KeyPackage>,
        CapabilityClaims,
        RequestProof,
    )> {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )?;
        let manifest = Manifest {
            schema_version: 1,
            cluster_id: "test-quorum".to_string(),
            epoch: 1,
            members: (1..=3)
                .map(|identifier| ipars_quorum::Member {
                    identifier,
                    node_id: format!("node-{identifier}"),
                    endpoint: format!("http://127.0.0.1:{}", 19000 + identifier),
                })
                .collect(),
            public_key_package: public.serialize()?,
        };
        let mut keys = Vec::new();
        for member in &manifest.members {
            let id = frost::Identifier::try_from(member.identifier)?;
            keys.push(frost::keys::KeyPackage::try_from(
                shares.get(&id).ok_or("missing share")?.clone(),
            )?);
        }
        let requester = SigningKey::from_bytes(&[7; 32]);
        let now = u64::try_from(Utc::now().timestamp())?;
        let claims = CapabilityClaims {
            schema_version: 1,
            cluster_id: manifest.cluster_id.clone(),
            epoch: manifest.epoch,
            manifest_digest: manifest.digest()?,
            method: "PUT".to_string(),
            path: "/v1/admin/policy".to_string(),
            body_sha256: Sha256::digest(b" { }\n").into(),
            requester_public_key: requester.verifying_key().to_bytes(),
            request_id: [9; 32],
            issued_at: now,
            expires_at: now + 120,
        };
        let proof = RequestProof {
            signature: requester.sign(&claims.proof_bytes()).to_bytes().to_vec(),
        };
        Ok((manifest, keys, claims, proof))
    }

    fn signed_token(
        manifest: &Manifest,
        keys: &[frost::keys::KeyPackage],
        claims: &CapabilityClaims,
        proof: &RequestProof,
    ) -> TestResult<CapabilityToken> {
        let mut a = SignerEngine::new(manifest.clone(), "node-1", keys[0].clone(), 4, 60)?;
        let mut b = SignerEngine::new(manifest.clone(), "node-2", keys[1].clone(), 4, 60)?;
        let ra = a.round1(claims, proof, claims.issued_at)?;
        let rb = b.round1(claims, proof, claims.issued_at)?;
        let ida = frost::Identifier::try_from(ra.identifier)?;
        let idb = frost::Identifier::try_from(rb.identifier)?;
        let package = frost::SigningPackage::new(
            BTreeMap::from([(ida, ra.commitments), (idb, rb.commitments)]),
            &claims.signing_bytes(),
        );
        let sa = a.round2(ra.session_id, claims, &package, claims.issued_at)?;
        let sb = b.round2(rb.session_id, claims, &package, claims.issued_at)?;
        let signature = frost::aggregate(
            &package,
            &BTreeMap::from([(ida, sa), (idb, sb)]),
            &manifest.public_keys()?,
        )?;
        Ok(CapabilityToken {
            claims: claims.clone(),
            signature: signature.serialize()?,
        })
    }

    fn test_plane(store: Arc<InMemoryStore>) -> TestResult<Arc<ControlPlane<InMemoryStore>>> {
        Ok(Arc::new(ControlPlane::new(
            ControlPlaneConfig::new(
                ipars_types::ClusterId::from_string("test-quorum"),
                "100.64.0.0/24".parse()?,
            ),
            store,
        )))
    }

    fn http_state(
        plane: Arc<ControlPlane<InMemoryStore>>,
    ) -> super::super::ControlPlaneHttpState<InMemoryStore, ipars_control_plane::InMemoryTokenLedger>
    {
        let join = Arc::new(ipars_control_plane::ControlPlaneJoinService::new(
            plane.clone(),
            Arc::new(ipars_control_plane::InMemoryTokenLedger::default()),
            ipars_control_plane::IssuerKeyRing::default(),
        ));
        super::super::ControlPlaneHttpState::new(plane, join)
            .require_operator_api_bearer_token("test-operator-token".to_string())
    }

    #[tokio::test]
    async fn legacy_mutation_rechecks_anchor_after_delayed_oidc() -> TestResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (started, resume) = (entered.clone(), release.clone());
        let provider = Router::new().route(
            "/realms/test/protocol/openid-connect/userinfo",
            get(move || {
                let (started, resume) = (started.clone(), resume.clone());
                async move {
                    started.notify_one();
                    resume.notified().await;
                    Json(serde_json::json!({"sub":"owner", "email":"owner@example.test"}))
                }
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, provider).await;
        });
        let oidc = WebUiAuthConfig::new(
            super::super::WebAuthProvider::Keycloak,
            "https://issuer.example.test/realms/test".into(),
            "test-client".into(),
            None,
            Some(format!("http://{address}/realms/test")),
            "openid".into(),
        )?
        .with_required_email("owner@example.test".into())?
        .with_required_subject("owner".into())?;
        let plane = test_plane(Arc::new(InMemoryStore::default()))?;
        let auth = Arc::new(super::super::ManagementAuth {
            operator_api_bearer_token: None,
            web_ui_auth: Some(Arc::new(oidc)),
            quorum_verifier: None,
            quorum_anchor_probe: anchor_probe(plane.clone()),
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let app = Router::new()
            .route(
                "/v1/admin/policy",
                post(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    async { StatusCode::OK }
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                auth,
                super::super::require_management_auth,
            ));
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/admin/policy")
            .header("authorization", "Bearer owner-token")
            .body(Body::empty())?;
        let pending = tokio::spawn(async move { app.oneshot(request).await });
        let started = timeout(Duration::from_secs(3), entered.notified()).await;
        if started.is_err() {
            pending.abort();
            server.abort();
            return Err("OIDC request did not start".into());
        }
        let (manifest, _, _, _) = fixture()?;
        plane
            .bind_admin_quorum_manifest(manifest.epoch, &manifest.digest()?)
            .await?;
        release.notify_one();
        let response = pending.await??;
        server.abort();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn preexisting_unconfigured_cp_observes_later_shared_anchor_and_fails_closed(
    ) -> TestResult {
        let (manifest, _, _, _) = fixture()?;
        let store = Arc::new(InMemoryStore::default());
        let plane_a = test_plane(store.clone())?;
        let plane_b = test_plane(store)?;
        let auth = Arc::new(super::super::ManagementAuth {
            operator_api_bearer_token: Some(Arc::from("test-operator-token")),
            web_ui_auth: None,
            quorum_verifier: None,
            quorum_anchor_probe: anchor_probe(plane_a),
        });
        let app = Router::new()
            .route(
                "/v1/admin/policy",
                axum::routing::put(|| async { StatusCode::OK }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                auth,
                super::super::require_management_auth,
            ));
        let request = || {
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/admin/policy")
                .header(header::AUTHORIZATION, "Bearer test-operator-token")
                .body(Body::empty())
        };
        assert_eq!(
            app.clone().oneshot(request()?).await?.status(),
            StatusCode::OK
        );
        plane_b
            .bind_admin_quorum_manifest(manifest.epoch, &manifest.digest()?)
            .await?;
        assert_eq!(
            app.oneshot(request()?).await?.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let failing_auth = Arc::new(super::super::ManagementAuth {
            operator_api_bearer_token: Some(Arc::from("test-operator-token")),
            web_ui_auth: None,
            quorum_verifier: None,
            quorum_anchor_probe: Arc::new(|| Box::pin(async { Err(()) })),
        });
        let app = Router::new()
            .route(
                "/v1/admin/policy",
                axum::routing::put(|| async { StatusCode::OK }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                failing_auth,
                super::super::require_management_auth,
            ));
        assert_eq!(
            app.oneshot(request()?).await?.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        Ok(())
    }

    #[tokio::test]
    async fn revocation_http_requires_exact_capability_and_blocks_target_execution() -> TestResult {
        let (manifest, keys, claims, proof) = fixture()?;
        let target_token = signed_token(&manifest, &keys, &claims, &proof)?;
        let plane = test_plane(Arc::new(InMemoryStore::default()))?;
        plane
            .bind_admin_quorum_manifest(manifest.epoch, &manifest.digest()?)
            .await?;
        plane
            .publish_admin_quorum_manifest(manifest.clone())
            .await?;
        let app =
            super::super::router(http_state(plane).with_admin_quorum_manifest(manifest.clone())?);
        let body = serde_json::to_string(&RevocationRequest {
            request_id: hex_bytes(&claims.request_id),
        })?;
        let mut revoke_claims = claims.clone();
        revoke_claims.request_id = [10; 32];
        revoke_claims.method = "POST".to_string();
        revoke_claims.path = REVOCATIONS_PATH.to_string();
        revoke_claims.body_sha256 = Sha256::digest(body.as_bytes()).into();
        let revoke_proof = RequestProof {
            signature: SigningKey::from_bytes(&[7; 32])
                .sign(&revoke_claims.proof_bytes())
                .to_bytes()
                .to_vec(),
        };
        let revoke_token = signed_token(&manifest, &keys, &revoke_claims, &revoke_proof)?;
        let bare = Request::builder()
            .method(Method::POST)
            .uri(REVOCATIONS_PATH)
            .header(header::AUTHORIZATION, "Bearer test-operator-token")
            .body(Body::from(body.clone()))?;
        assert_eq!(
            app.clone().oneshot(bare).await?.status(),
            StatusCode::UNAUTHORIZED
        );
        let wrong_path =
            authorized_request(&target_token, &proof, "POST", REVOCATIONS_PATH, &body)?;
        assert_eq!(
            app.clone().oneshot(wrong_path).await?.status(),
            StatusCode::UNAUTHORIZED
        );
        let wrong_target = body.replace(&hex_bytes(&claims.request_id), &"a".repeat(64));
        assert_eq!(
            app.clone()
                .oneshot(authorized_request(
                    &revoke_token,
                    &revoke_proof,
                    "POST",
                    REVOCATIONS_PATH,
                    &wrong_target
                )?)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = app
            .clone()
            .oneshot(authorized_request(
                &revoke_token,
                &revoke_proof,
                "POST",
                REVOCATIONS_PATH,
                &body,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let result: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024).await?)?;
        assert_eq!(result, serde_json::json!({"revoked":true}));
        let response = app
            .clone()
            .oneshot(authorized_request(
                &target_token,
                &proof,
                "PUT",
                &claims.path,
                " { }\n",
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .oneshot(authorized_request(
                &revoke_token,
                &revoke_proof,
                "POST",
                REVOCATIONS_PATH,
                &body,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        for invalid in [
            serde_json::json!({"request_id":"x".repeat(64)}),
            serde_json::json!({"request_id":"0".repeat(63)}),
            serde_json::json!({"request_id":"0".repeat(64),"epoch":2}),
        ] {
            assert!(parse_revocation(&serde_json::to_vec(&invalid)?).is_err());
        }
        Ok(())
    }

    fn admin_app(verifier: QuorumVerifier) -> Router {
        let auth = Arc::new(super::super::ManagementAuth {
            operator_api_bearer_token: Some(Arc::from("test-operator-token")),
            web_ui_auth: None,
            quorum_verifier: Some(Arc::new(verifier)),
            quorum_anchor_probe: Arc::new(|| Box::pin(async { Ok(false) })),
        });
        Router::new()
            .route(
                "/v1/admin/policy",
                axum::routing::put(|body: Bytes| async move { body })
                    .post(|| async { StatusCode::OK }),
            )
            .route("/v1/admin/enrollment", post(|| async { StatusCode::OK }))
            .route_layer(axum::middleware::from_fn_with_state(
                auth,
                super::super::require_management_auth,
            ))
    }

    fn authorized_request(
        token: &CapabilityToken,
        proof: &RequestProof,
        method: &str,
        path: &str,
        body: &str,
    ) -> TestResult<Request> {
        Ok(Request::builder()
            .method(method)
            .uri(path)
            .header(
                QUORUM_TOKEN_HEADER,
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(token)?),
            )
            .header(
                QUORUM_PROOF_HEADER,
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(proof)?),
            )
            .header(header::AUTHORIZATION, "Bearer test-operator-token")
            .body(Body::from(body.to_owned()))?)
    }

    #[tokio::test]
    async fn real_capability_tampering_rejected_and_replay_shared_across_control_planes(
    ) -> TestResult {
        let (manifest, keys, claims, proof) = fixture()?;
        let token = signed_token(&manifest, &keys, &claims, &proof)?;
        let store = Arc::new(InMemoryStore::default());
        let plane_a = test_plane(store.clone())?;
        let plane_b = test_plane(store)?;
        plane_a
            .bind_admin_quorum_manifest(manifest.epoch, &manifest.digest()?)
            .await?;
        plane_a
            .publish_admin_quorum_manifest(manifest.clone())
            .await?;
        let a = admin_app(QuorumVerifier::new(manifest.clone(), plane_a)?);
        let b = admin_app(QuorumVerifier::new(manifest, plane_b)?);
        for (method, path, body) in [
            ("PUT", "/v1/admin/policy", "{}"),
            ("POST", "/v1/admin/policy", " { }\n"),
            ("POST", "/v1/admin/enrollment", " { }\n"),
            ("PUT", "/v1/admin/policy?unsigned=1", " { }\n"),
        ] {
            let response = a
                .clone()
                .oneshot(authorized_request(&token, &proof, method, path, body)?)
                .await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let mut bad_proof = proof.clone();
        bad_proof.signature[0] ^= 1;
        let response = a
            .clone()
            .oneshot(authorized_request(
                &token,
                &bad_proof,
                "PUT",
                &claims.path,
                " { }\n",
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let mut bad_token = token.clone();
        bad_token.signature[0] ^= 1;
        let response = a
            .clone()
            .oneshot(authorized_request(
                &bad_token,
                &proof,
                "PUT",
                &claims.path,
                " { }\n",
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let request_a = authorized_request(&token, &proof, "PUT", &claims.path, " { }\n")?;
        let request_b = authorized_request(&token, &proof, "PUT", &claims.path, " { }\n")?;
        let (ra, rb) = tokio::join!(a.oneshot(request_a), b.oneshot(request_b));
        let ra = ra?;
        let rb = rb?;
        assert!(matches!(
            (ra.status(), rb.status()),
            (StatusCode::OK, StatusCode::UNAUTHORIZED) | (StatusCode::UNAUTHORIZED, StatusCode::OK)
        ));
        let successful = if ra.status() == StatusCode::OK {
            ra
        } else {
            rb
        };
        assert_eq!(
            to_bytes(successful.into_body(), 128).await?.as_ref(),
            b" { }\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unbound_manifest_and_revoked_capability_fail_closed() -> TestResult {
        let (manifest, keys, claims, proof) = fixture()?;
        let token = signed_token(&manifest, &keys, &claims, &proof)?;
        let plane = test_plane(Arc::new(InMemoryStore::default()))?;
        let app = admin_app(QuorumVerifier::new(manifest.clone(), plane.clone())?);
        let response = app
            .clone()
            .oneshot(authorized_request(
                &token,
                &proof,
                "PUT",
                &claims.path,
                " { }\n",
            )?)
            .await?;
        assert_ne!(response.status(), StatusCode::OK);
        plane
            .bind_admin_quorum_manifest(manifest.epoch, &manifest.digest()?)
            .await?;
        plane
            .publish_admin_quorum_manifest(manifest.clone())
            .await?;
        let mut incompatible = manifest.clone();
        incompatible.epoch += 1;
        let mut other_claims = claims.clone();
        other_claims.epoch = incompatible.epoch;
        other_claims.manifest_digest = incompatible.digest()?;
        let other_proof = RequestProof {
            signature: SigningKey::from_bytes(&[7; 32])
                .sign(&other_claims.proof_bytes())
                .to_bytes()
                .to_vec(),
        };
        let other_token = signed_token(&incompatible, &keys, &other_claims, &other_proof)?;
        let other_app = admin_app(QuorumVerifier::new(incompatible, plane.clone())?);
        let response = other_app
            .oneshot(authorized_request(
                &other_token,
                &other_proof,
                "PUT",
                &claims.path,
                " { }\n",
            )?)
            .await?;
        assert_ne!(response.status(), StatusCode::OK);
        assert!(
            plane
                .revoke_admin_capability(ipars_control_plane::AdminCapabilityRevocation {
                    cluster_id: plane.config().cluster_id.clone(),
                    manifest_epoch: manifest.epoch,
                    manifest_digest: manifest.digest()?,
                    request_id: hex_bytes(&claims.request_id),
                    expires_at: DateTime::from_timestamp(i64::try_from(claims.expires_at)?, 0)
                        .ok_or("invalid expiry")?,
                    received_at: Utc::now(),
                    method: "POST".to_string(),
                    path: "/v1/admin/quorum/revoke".to_string(),
                    requester_public_key: hex_bytes(&claims.requester_public_key),
                })
                .await?
        );
        let response = app
            .oneshot(authorized_request(
                &token,
                &proof,
                "PUT",
                &claims.path,
                " { }\n",
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn signer_http_rounds_require_owner_and_proof_and_produce_majority_signature(
    ) -> TestResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (manifest, keys, claims, proof) = fixture()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let provider = Router::new().route(
            "/realms/test/protocol/openid-connect/userinfo",
            get(move |headers: HeaderMap| {
                count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        == Some("Bearer test-owner-token")
                    {
                        Json(serde_json::json!({"sub":"owner", "email":"owner@example.test"}))
                            .into_response()
                    } else {
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, provider).await;
        });
        let auth = WebUiAuthConfig::new(
            super::super::WebAuthProvider::Keycloak,
            "https://issuer.example.test/realms/test".to_string(),
            "test-client".to_string(),
            None,
            Some(format!("http://{address}/realms/test")),
            "openid".to_string(),
        )?
        .with_required_email("owner@example.test".to_string())?
        .with_required_subject("owner".to_string())?;
        let a = signer_router(manifest.clone(), keys[0].clone(), "node-1", auth.clone())?;
        let b = signer_router(manifest.clone(), keys[1].clone(), "node-2", auth)?;
        let round_one = Round1Request {
            claims: claims.clone(),
            proof: proof.clone(),
        };
        let rejected_operator = a
            .clone()
            .oneshot(signer_request(
                "/v1/quorum/round1",
                &round_one,
                "test-operator-token",
            )?)
            .await?;
        assert_eq!(rejected_operator.status(), StatusCode::UNAUTHORIZED);
        let ra: ipars_quorum::Round1Response =
            signer_response(a.clone(), "/v1/quorum/round1", &round_one).await?;
        let rb: ipars_quorum::Round1Response =
            signer_response(b.clone(), "/v1/quorum/round1", &round_one).await?;
        let ida = frost::Identifier::try_from(ra.identifier)?;
        let idb = frost::Identifier::try_from(rb.identifier)?;
        let package = frost::SigningPackage::new(
            BTreeMap::from([(ida, ra.commitments), (idb, rb.commitments)]),
            &claims.signing_bytes(),
        );
        let mut round_two = Round2Request {
            session_id: ra.session_id,
            claims: claims.clone(),
            proof: proof.clone(),
            signing_package: package.clone(),
        };
        let rejected_operator = a
            .clone()
            .oneshot(signer_request(
                "/v1/quorum/round2",
                &round_two,
                "test-operator-token",
            )?)
            .await?;
        assert_eq!(rejected_operator.status(), StatusCode::UNAUTHORIZED);
        round_two.proof.signature[0] ^= 1;
        let bad_pop = a
            .clone()
            .oneshot(signer_request(
                "/v1/quorum/round2",
                &round_two,
                "test-owner-token",
            )?)
            .await?;
        assert_eq!(bad_pop.status(), StatusCode::BAD_REQUEST);
        let error_body = to_bytes(bad_pop.into_body(), 1024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&error_body)?,
            serde_json::json!({"error":"quorum signing request rejected"})
        );
        round_two.proof = proof.clone();
        let sa: Round2Response =
            signer_response(a.clone(), "/v1/quorum/round2", &round_two).await?;
        let replay = a
            .oneshot(signer_request(
                "/v1/quorum/round2",
                &round_two,
                "test-owner-token",
            )?)
            .await?;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        round_two.session_id = rb.session_id;
        let sb: Round2Response = signer_response(b, "/v1/quorum/round2", &round_two).await?;
        let signature = frost::aggregate(
            &package,
            &BTreeMap::from([(ida, sa.signature_share), (idb, sb.signature_share)]),
            &manifest.public_keys()?,
        )?;
        let token = CapabilityToken {
            claims: claims.clone(),
            signature: signature.serialize()?,
        };
        ipars_quorum::verify_capability(
            &manifest,
            &token,
            &proof,
            "PUT",
            &claims.path,
            b" { }\n",
            claims.issued_at,
        )?;
        assert_eq!(calls.load(Ordering::SeqCst), 8);
        server.abort();
        Ok(())
    }

    fn signer_request<T: Serialize>(path: &str, body: &T, bearer: &str) -> TestResult<Request> {
        Ok(Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body)?))?)
    }

    async fn signer_response<T: Serialize, R: DeserializeOwned>(
        app: Router,
        path: &str,
        body: &T,
    ) -> TestResult<R> {
        let response = app
            .oneshot(signer_request(path, body, "test-owner-token")?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_SIGNER_BODY_BYTES).await?,
        )?)
    }

    #[tokio::test]
    async fn strict_gate_rejects_operator_mutations_but_preserves_get_auth(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use axum::{middleware, routing::get, Router};
        let verifier = Arc::new(QuorumVerifier {
            verify_and_consume: Arc::new(|_| {
                Box::pin(async {
                    Err(rejected(
                        StatusCode::UNAUTHORIZED,
                        "quorum authorization required",
                    ))
                })
            }),
        });
        let auth = Arc::new(super::super::ManagementAuth {
            operator_api_bearer_token: Some(Arc::from("test-operator-token")),
            web_ui_auth: None,
            quorum_verifier: Some(verifier),
            quorum_anchor_probe: Arc::new(|| Box::pin(async { Ok(false) })),
        });
        let app = Router::new()
            .route(
                "/v1/admin/policy",
                get(|| async { StatusCode::OK })
                    .post(|| async { StatusCode::OK })
                    .put(|| async { StatusCode::OK })
                    .delete(|| async { StatusCode::OK })
                    .patch(|| async { StatusCode::OK }),
            )
            .route_layer(middleware::from_fn_with_state(
                auth,
                super::super::require_management_auth,
            ));
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            for token in [None, Some("test-operator-token")] {
                let mut builder = Request::builder()
                    .method(method.clone())
                    .uri("/v1/admin/policy");
                if let Some(token) = token {
                    builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
                }
                let response = app.clone().oneshot(builder.body(Body::empty())?).await?;
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
        }
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/policy")
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }

    #[test]
    fn all_non_read_methods_require_quorum() {
        for method in [
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::CONNECT,
            Method::TRACE,
        ] {
            assert!(mutating(&method));
        }
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!mutating(&method));
        }
    }

    #[test]
    fn duplicate_and_oversized_auth_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer first"),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert!(unique_header(&headers, "authorization").is_none());
        headers.clear();
        if let Ok(value) = HeaderValue::from_str(&"a".repeat(MAX_QUORUM_HEADER_BYTES + 1)) {
            headers.insert(header::AUTHORIZATION, value);
        }
        assert!(unique_header(&headers, "authorization").is_none());
    }

    #[test]
    fn quorum_headers_require_bounded_single_base64url_json_values(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        assert!(decode_header::<serde_json::Value>(&headers, QUORUM_TOKEN_HEADER).is_none());
        headers.insert(QUORUM_TOKEN_HEADER, HeaderValue::from_static("invalid!"));
        assert!(decode_header::<serde_json::Value>(&headers, QUORUM_TOKEN_HEADER).is_none());
        let encoded = URL_SAFE_NO_PAD.encode(br#"{"request_id":"test"}"#);
        headers.insert(QUORUM_TOKEN_HEADER, HeaderValue::from_str(&encoded)?);
        assert!(decode_header::<serde_json::Value>(&headers, QUORUM_TOKEN_HEADER).is_some());
        headers.append(QUORUM_TOKEN_HEADER, HeaderValue::from_str(&encoded)?);
        assert!(decode_header::<serde_json::Value>(&headers, QUORUM_TOKEN_HEADER).is_none());
        Ok(())
    }

    #[tokio::test]
    async fn body_limit_and_exact_bytes_are_preserved() -> Result<(), Box<dyn std::error::Error>> {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/admin/policy?x=1")
            .body(Body::from(" { \"x\": 1 }\n"))?;
        let Ok((parts, bytes)) = bounded_body(request, 128).await else {
            return Err("body unexpectedly rejected".into());
        };
        assert_eq!(
            parts.uri.path_and_query().map(|value| value.as_str()),
            Some("/v1/admin/policy?x=1")
        );
        assert_eq!(bytes.as_ref(), b" { \"x\": 1 }\n");
        let oversized = Request::new(Body::from("x".repeat(129)));
        let Err(response) = bounded_body(oversized, 128).await else {
            return Err("oversized body accepted".into());
        };
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        Ok(())
    }

    #[tokio::test]
    async fn signer_owner_auth_is_revalidated_for_each_round(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use axum::{routing::get, Router};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let app = Router::new().route(
            "/realms/test/protocol/openid-connect/userinfo",
            get(move || {
                let first = count.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    if first {
                        Json(serde_json::json!({"sub":"owner", "email":"owner@example.test"}))
                            .into_response()
                    } else {
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let auth = WebUiAuthConfig::new(
            super::super::WebAuthProvider::Keycloak,
            "https://issuer.example.test/realms/test".to_string(),
            "test-client".to_string(),
            None,
            Some(format!("http://{address}/realms/test")),
            "openid".to_string(),
        )?
        .with_required_email("owner@example.test".to_string())?
        .with_required_subject("owner".to_string())?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-owner-token"),
        );
        assert!(require_owner(&auth, &headers).await.is_ok());
        let second = require_owner(&auth, &headers).await;
        server.abort();
        let Err(response) = second else {
            return Err("round two reused owner authentication".into());
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let mut missing_owner = auth;
        missing_owner.required_email = None;
        assert!(require_owner(&missing_owner, &headers).await.is_err());
        assert!(SignerHttpAuth::new(missing_owner).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn matching_email_cannot_replace_pinned_owner_subject() -> TestResult {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let provider = Router::new().route(
            "/realms/test/protocol/openid-connect/userinfo",
            get(|| async {
                Json(serde_json::json!({"sub":"different-subject", "email":"owner@example.test"}))
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, provider).await;
        });
        let unpinned = WebUiAuthConfig::new(
            super::super::WebAuthProvider::Keycloak,
            "https://issuer.example.test/realms/test".to_string(),
            "test-client".to_string(),
            None,
            Some(format!("http://{address}/realms/test")),
            "openid".to_string(),
        )?
        .with_required_email("owner@example.test".to_string())?;
        assert!(SignerHttpAuth::new(unpinned.clone()).is_err());
        assert!(unpinned.validate_access_token("test-owner-token").await);
        for invalid in ["", " owner", "owner\n"] {
            assert!(unpinned
                .clone()
                .with_required_subject(invalid.to_string())
                .is_err());
        }
        let pinned = unpinned.with_required_subject("immutable-owner-subject".to_string())?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-owner-token"),
        );
        let result = SignerHttpAuth::new(pinned)?.authenticate(&headers).await;
        server.abort();
        let Err(response) = result else {
            return Err("same-email attacker authenticated".into());
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn saturated_signer_rejects_without_calling_oidc(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = WebUiAuthConfig::new(
            super::super::WebAuthProvider::Keycloak,
            "https://issuer.example.test/realms/test".to_string(),
            "test-client".to_string(),
            None,
            None,
            "openid".to_string(),
        )?
        .with_required_email("owner@example.test".to_string())?
        .with_required_subject("owner".to_string())?;
        let auth = SignerHttpAuth::new(owner)?;
        let _occupied = auth
            .capacity
            .clone()
            .try_acquire_many_owned(MAX_SIGNER_IN_FLIGHT as u32)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-owner-token"),
        );
        let result = timeout(Duration::from_millis(100), auth.authenticate(&headers)).await?;
        let Err(response) = result else {
            return Err("saturated signer accepted authentication".into());
        };
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        Ok(())
    }
}
