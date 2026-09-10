//! Rotation trust comes from local signer configuration and the shared CP anchor.
use super::*;
use ipars_quorum::{ManifestRotation, ManifestTransition, VerifiedRotation};

pub const MANIFEST_PATH: &str = "/v1/admin/quorum/manifest";
pub const ROTATION_PATH: &str = "/v1/admin/quorum/rotation";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationRound1Request {
    pub transition: ManifestTransition,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationRound2Request {
    pub session_id: [u8; 32],
    pub transition: ManifestTransition,
    pub signing_package: frost::SigningPackage,
}

struct RotationSignerState {
    auth: SignerHttpAuth,
    old: Manifest,
    engine: Mutex<SignerEngine>,
}

/// Explicit opt-in to rotation signing. `old` must be loaded from trusted local
/// configuration, never an HTTP request. A staged new signer does not authorize
/// normal capabilities until its group becomes active at the control plane.
pub fn signer_router_with_rotation_anchor(
    manifest: Manifest,
    key_package: frost::keys::KeyPackage,
    node_id: impl AsRef<str>,
    auth: WebUiAuthConfig,
    old: Manifest,
) -> Result<Router, String> {
    old.validate()
        .map_err(|_| "invalid trusted rotation anchor".to_string())?;
    manifest
        .validate()
        .map_err(|_| "invalid rotation signer manifest".to_string())?;
    if manifest.cluster_id != old.cluster_id
        || (manifest.digest().map_err(|_| "invalid manifest")?
            != old.digest().map_err(|_| "invalid anchor")?
            && old.epoch.checked_add(1) != Some(manifest.epoch))
    {
        return Err("rotation signer does not match the trusted old epoch".to_string());
    }
    let rotation_auth = SignerHttpAuth::new(auth.clone())?;
    let engine = SignerEngine::new(
        manifest.clone(),
        node_id.as_ref(),
        key_package.clone(),
        128,
        60,
    )
    .map_err(|_| "invalid rotation signer key".to_string())?;
    let rotation = Router::new()
        .route("/v1/quorum/rotation/round1", post(round1_rotation))
        .route("/v1/quorum/rotation/round2", post(round2_rotation))
        .with_state(Arc::new(RotationSignerState {
            auth: rotation_auth,
            old,
            engine: Mutex::new(engine),
        }));
    Ok(signer_router(manifest, key_package, node_id, auth)?.merge(rotation))
}

async fn round1_rotation(
    State(state): State<Arc<RotationSignerState>>,
    request: Request,
) -> Result<Response, Response> {
    let _permit = state.auth.authenticate(request.headers()).await?;
    let (_, bytes) = bounded_body(request, MAX_SIGNER_BODY_BYTES).await?;
    let request: RotationRound1Request = serde_json::from_slice(&bytes)
        .map_err(|_| rejected(StatusCode::BAD_REQUEST, "invalid rotation signing request"))?;
    let mut engine = state
        .engine
        .try_lock()
        .map_err(|_| rejected(StatusCode::TOO_MANY_REQUESTS, "rotation signer busy"))?;
    let response = engine
        .round1_rotation(
            &state.old,
            &request.transition,
            current_seconds().map_err(IntoResponse::into_response)?,
        )
        .map_err(round_error)?;
    Ok(Json(response).into_response())
}

async fn round2_rotation(
    State(state): State<Arc<RotationSignerState>>,
    request: Request,
) -> Result<Response, Response> {
    let _permit = state.auth.authenticate(request.headers()).await?;
    let (_, bytes) = bounded_body(request, MAX_SIGNER_BODY_BYTES).await?;
    let request: RotationRound2Request = serde_json::from_slice(&bytes)
        .map_err(|_| rejected(StatusCode::BAD_REQUEST, "invalid rotation signing request"))?;
    let mut engine = state
        .engine
        .try_lock()
        .map_err(|_| rejected(StatusCode::TOO_MANY_REQUESTS, "rotation signer busy"))?;
    let signature_share = engine
        .round2_rotation(
            request.session_id,
            &state.old,
            &request.transition,
            &request.signing_package,
            current_seconds().map_err(IntoResponse::into_response)?,
        )
        .map_err(round_error)?;
    Ok(Json(Round2Response { signature_share }).into_response())
}

pub(super) async fn load_active<S: ControlPlaneStore>(
    plane: &ControlPlane<S>,
) -> Result<Manifest, Response> {
    match timeout(
        Duration::from_secs(5),
        plane.get_active_admin_quorum_manifest(),
    )
    .await
    {
        Ok(Ok(Some(manifest))) => Ok(manifest),
        _ => Err(rejected(
            StatusCode::SERVICE_UNAVAILABLE,
            "active quorum manifest unavailable",
        )),
    }
}

pub(super) async fn authorize_rotation<S: ControlPlaneStore>(
    plane: &ControlPlane<S>,
    request: Request,
) -> Result<Request, Response> {
    if request.method() != Method::POST || request.uri().query().is_some() {
        return Err(rejected(
            StatusCode::UNAUTHORIZED,
            "rotation request binding rejected",
        ));
    }
    let (mut parts, bytes) = bounded_body(request, MAX_ADMIN_BODY_BYTES).await?;
    let rotation: ManifestRotation = serde_json::from_slice(&bytes)
        .map_err(|_| rejected(StatusCode::BAD_REQUEST, "invalid quorum rotation"))?;
    let old = load_active(plane).await?;
    let verified = ipars_quorum::verify_rotation(
        &old,
        &rotation,
        current_seconds().map_err(IntoResponse::into_response)?,
    )
    .map_err(|_| rejected(StatusCode::UNAUTHORIZED, "dual quorum rotation rejected"))?;
    parts.extensions.insert(verified);
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

pub(crate) async fn active_manifest<S, L>(
    State(state): State<super::super::ControlPlaneHttpState<S, L>>,
) -> Result<Response, Response>
where
    S: ControlPlaneStore + 'static,
    L: ipars_control_plane::TokenLedger + 'static,
{
    Ok(Json(load_active(state.plane.as_ref()).await?).into_response())
}

pub(crate) async fn apply_rotation<S, L>(
    State(state): State<super::super::ControlPlaneHttpState<S, L>>,
    request: Request,
) -> Result<Response, Response>
where
    S: ControlPlaneStore + 'static,
    L: ipars_control_plane::TokenLedger + 'static,
{
    let verified = request
        .extensions()
        .get::<VerifiedRotation>()
        .cloned()
        .ok_or_else(|| {
            rejected(
                StatusCode::UNAUTHORIZED,
                "dual quorum authorization required",
            )
        })?;
    match timeout(
        Duration::from_secs(5),
        state.plane.rotate_admin_quorum_manifest(verified),
    )
    .await
    {
        Ok(Ok(true)) => Ok(Json(serde_json::json!({"applied":true})).into_response()),
        Ok(Ok(false)) => Err(rejected(
            StatusCode::CONFLICT,
            "quorum rotation stale or already applied",
        )),
        _ => Err(rejected(
            StatusCode::SERVICE_UNAVAILABLE,
            "quorum rotation outcome unavailable; read active manifest",
        )),
    }
}
