use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Extension, Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::Utc;
use ipars_control_plane::customer_resources::{
    CreateCustomerProject, CreatePublicService, CustomerAccount, CustomerProject,
    CustomerProjectId, CustomerQuota, CustomerResourceError, CustomerResourceStore,
    EnsurePersonalAccount, KeycloakIdentity, KubernetesName, PublicServiceId,
    PublicServiceResource, PublicServiceSpec, PublicServiceStatus, MAX_CUSTOMER_RESOURCE_PAGE_SIZE,
};
use ipars_types::ClusterId;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::{
    bearer_token_from_headers, operator_api_token_matches, CustomerAccessTokenError,
    CustomerAuthConfig, CustomerOidcPrincipal,
};

const MAX_CUSTOMER_RESOURCE_REQUEST_BYTES: usize = 16 * 1024;
const DEFAULT_CUSTOMER_RESOURCE_PAGE_SIZE: usize = 100;

struct CustomerApiState<S> {
    store: Arc<S>,
    cluster_id: ClusterId,
    default_quota: CustomerQuota,
}

impl<S> Clone for CustomerApiState<S> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            cluster_id: self.cluster_id.clone(),
            default_quota: self.default_quota,
        }
    }
}

#[derive(Debug, Serialize)]
struct CustomerSessionResponse {
    principal: CustomerOidcPrincipal,
    account: CustomerAccount,
}

#[derive(Debug, Serialize)]
struct CustomerProjectsResponse {
    projects: Vec<CustomerProject>,
    next_cursor: Option<CustomerProjectId>,
}

#[derive(Debug, Serialize)]
struct CustomerProjectResponse {
    project: CustomerProject,
}

#[derive(Debug, Serialize)]
struct PublicServicesResponse {
    public_services: Vec<PublicServiceResource>,
    next_cursor: Option<PublicServiceId>,
}

#[derive(Debug, Serialize)]
struct ControllerDesiredResourcesResponse {
    projects: Vec<CustomerProject>,
    public_services: Vec<PublicServiceResource>,
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct PublicServiceResponse {
    public_service: PublicServiceResource,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProjectRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePublicServiceRequest {
    name: String,
    spec: PublicServiceSpec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerStatusRequest {
    expected_generation: u64,
    status: PublicServiceStatus,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomerPageQuery {
    cursor: Option<String>,
    #[serde(default = "default_customer_page_size")]
    limit: usize,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControllerDesiredResourceKind {
    Projects,
    PublicServices,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerDesiredResourcesQuery {
    kind: ControllerDesiredResourceKind,
    cursor: Option<String>,
    #[serde(default = "max_customer_page_size")]
    limit: usize,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: String,
}

struct CustomerApiError {
    status: StatusCode,
    message: String,
    retry_after: bool,
}

impl From<CustomerResourceError> for CustomerApiError {
    fn from(error: CustomerResourceError) -> Self {
        let (status, message, retry_after) = match error {
            CustomerResourceError::Validation { .. } => {
                (StatusCode::BAD_REQUEST, error.to_string(), false)
            }
            CustomerResourceError::AccountNotFound { .. }
            | CustomerResourceError::ProjectNotFound { .. }
            | CustomerResourceError::PublicServiceNotFound { .. }
            | CustomerResourceError::OwnershipMismatch { .. } => (
                StatusCode::NOT_FOUND,
                "customer resource was not found".to_string(),
                false,
            ),
            CustomerResourceError::DuplicateName { .. }
            | CustomerResourceError::QuotaExceeded { .. }
            | CustomerResourceError::ClusterCapacityExceeded { .. }
            | CustomerResourceError::GenerationConflict { .. }
            | CustomerResourceError::StatusObservationConflict { .. }
            | CustomerResourceError::IdentifierCollision { .. } => {
                (StatusCode::CONFLICT, error.to_string(), false)
            }
            CustomerResourceError::Store(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "customer resource store is temporarily unavailable".to_string(),
                true,
            ),
        };
        Self {
            status,
            message,
            retry_after,
        }
    }
}

impl IntoResponse for CustomerApiError {
    fn into_response(self) -> Response {
        let body = Json(ApiErrorBody {
            error: self.message,
        });
        if self.retry_after {
            (
                self.status,
                [
                    (header::RETRY_AFTER, "5"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                body,
            )
                .into_response()
        } else {
            (self.status, [(header::CACHE_CONTROL, "no-store")], body).into_response()
        }
    }
}

pub fn customer_router<S>(
    store: Arc<S>,
    cluster_id: ClusterId,
    auth: CustomerAuthConfig,
    default_quota: CustomerQuota,
) -> Router
where
    S: CustomerResourceStore + 'static,
{
    let state = CustomerApiState {
        store,
        cluster_id,
        default_quota,
    };
    let protected = Router::new()
        .route("/v1/customer/session", get(customer_session::<S>))
        .route(
            "/v1/customer/projects",
            get(list_projects::<S>).post(create_project::<S>),
        )
        .route(
            "/v1/customer/projects/{project_id}",
            get(get_project::<S>).delete(delete_project::<S>),
        )
        .route(
            "/v1/customer/projects/{project_id}/public-services",
            get(list_public_services::<S>).post(create_public_service::<S>),
        )
        .route(
            "/v1/customer/projects/{project_id}/public-services/{resource_id}",
            get(get_public_service::<S>).delete(delete_public_service::<S>),
        )
        .layer(DefaultBodyLimit::max(MAX_CUSTOMER_RESOURCE_REQUEST_BYTES))
        .route_layer(middleware::from_fn_with_state(
            Arc::new(auth),
            require_customer_auth,
        ));
    Router::new()
        .route("/healthz", get(customer_healthz))
        .merge(protected)
        .with_state(state)
}

pub fn customer_controller_router<S>(
    store: Arc<S>,
    cluster_id: ClusterId,
    bearer_token: String,
) -> Result<Router, String>
where
    S: CustomerResourceStore + 'static,
{
    if bearer_token.len() < 32
        || bearer_token.len() > 512
        || bearer_token.contains(char::is_whitespace)
        || bearer_token.chars().any(char::is_control)
    {
        return Err(
            "customer controller bearer token must be 32 to 512 non-whitespace bytes".to_string(),
        );
    }
    let state = CustomerApiState {
        store,
        cluster_id,
        default_quota: CustomerQuota::default(),
    };
    let protected = Router::new()
        .route(
            "/internal/v1/customer/public-services",
            get(list_desired_public_services::<S>),
        )
        .route(
            "/internal/v1/customer/public-services/{resource_id}/status",
            put(update_public_service_status::<S>),
        )
        .layer(DefaultBodyLimit::max(MAX_CUSTOMER_RESOURCE_REQUEST_BYTES))
        .route_layer(middleware::from_fn_with_state(
            Arc::<str>::from(bearer_token),
            require_customer_controller_bearer,
        ));
    Ok(Router::new()
        .route("/healthz", get(customer_healthz))
        .merge(protected)
        .with_state(state))
}

async fn require_customer_auth(
    State(auth): State<Arc<CustomerAuthConfig>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = bearer_token_from_headers(request.headers()) else {
        return customer_auth_rejection(
            StatusCode::UNAUTHORIZED,
            "customer API bearer token is required",
            false,
        );
    };
    match auth.validate_access_token(token).await {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(CustomerAccessTokenError::Unauthorized) => customer_auth_rejection(
            StatusCode::UNAUTHORIZED,
            "customer API authentication was rejected",
            false,
        ),
        Err(CustomerAccessTokenError::Forbidden) => customer_auth_rejection(
            StatusCode::FORBIDDEN,
            "customer API role is required",
            false,
        ),
        Err(CustomerAccessTokenError::Unavailable) => customer_auth_rejection(
            StatusCode::SERVICE_UNAVAILABLE,
            "customer identity provider is temporarily unavailable",
            true,
        ),
        Err(CustomerAccessTokenError::RateLimited) => customer_auth_rejection(
            StatusCode::TOO_MANY_REQUESTS,
            "customer authentication rate limit was exceeded",
            true,
        ),
    }
}

async fn require_customer_controller_bearer(
    State(expected): State<Arc<str>>,
    request: Request,
    next: Next,
) -> Response {
    let provided = bearer_token_from_headers(request.headers());
    if !provided.is_some_and(|provided| operator_api_token_matches(&expected, provided)) {
        return customer_auth_rejection(
            StatusCode::UNAUTHORIZED,
            "customer controller bearer token was rejected",
            false,
        );
    }
    next.run(request).await
}

fn customer_auth_rejection(status: StatusCode, message: &str, retry_after: bool) -> Response {
    let body = Json(ApiErrorBody {
        error: message.to_string(),
    });
    if retry_after {
        (
            status,
            [
                (header::RETRY_AFTER, "5"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response()
    } else if status == StatusCode::UNAUTHORIZED {
        (
            status,
            [
                (header::WWW_AUTHENTICATE, "Bearer"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response()
    } else {
        (status, [(header::CACHE_CONTROL, "no-store")], body).into_response()
    }
}

async fn customer_healthz() -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"status": "ok"})),
    )
}

async fn customer_session<S>(
    State(state): State<CustomerApiState<S>>,
    Extension(principal): Extension<CustomerOidcPrincipal>,
) -> Result<Json<CustomerSessionResponse>, CustomerApiError>
where
    S: CustomerResourceStore,
{
    let account = ensure_account(&state, &principal).await?;
    Ok(Json(CustomerSessionResponse { principal, account }))
}

async fn list_projects<S>(
    State(state): State<CustomerApiState<S>>,
    Extension(principal): Extension<CustomerOidcPrincipal>,
    Query(query): Query<CustomerPageQuery>,
) -> Result<Json<CustomerProjectsResponse>, CustomerApiError>
where
    S: CustomerResourceStore,
{
    let account = ensure_account(&state, &principal).await?;
    let cursor = query.cursor.map(CustomerProjectId::parse).transpose()?;
    let page = state
        .store
        .list_customer_projects(
            &state.cluster_id,
            &account.account_id,
            cursor.as_ref(),
            query.limit,
        )
        .await?;
    Ok(Json(CustomerProjectsResponse {
        projects: page.projects,
        next_cursor: page.next_cursor,
    }))
}

async fn create_project<S>(
    State(state): State<CustomerApiState<S>>,
    Extension(principal): Extension<CustomerOidcPrincipal>,
    Json(request): Json<CreateProjectRequest>,
) -> Result<(StatusCode, Json<CustomerProjectResponse>), CustomerApiError>
where
    S: CustomerResourceStore,
{
    let account = ensure_account(&state, &principal).await?;
    let project = state
        .store
        .create_customer_project(CreateCustomerProject {
            cluster_id: state.cluster_id.clone(),
            account_id: account.account_id,
            name: KubernetesName::parse(request.name)?,
            created_at: Utc::now(),
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(CustomerProjectResponse { project }),
    ))
}

async fn get_project<S>(
    State(state): State<CustomerApiState<S>>,
    Extension(principal): Extension<CustomerOidcPrincipal>,
    Path(project_id): Path<String>,
) -> Result<Json<CustomerProjectResponse>, CustomerApiError>
where
    S: CustomerResourceStore,
{
    let account = ensure_account(&state, &principal).await?;
    let project_id = CustomerProjectId::parse(project_id)?;
    let project = state
        .store
        .get_customer_project(&state.cluster_id, &account.account_id, &project_id)
        .await?
        .ok_or(CustomerResourceError::ProjectNotFound {
            cluster_id: state.cluster_id,
            project_id,
        })?;
    Ok(Json(CustomerProjectResponse { project }))
}

async fn delete_project<S>(
    State(state): State<CustomerApiState<S>>,
    Extension(principal): Extension<CustomerOidcPrincipal>,
    Path(project_id): Path<String>,
) -> Result<StatusCode, CustomerApiError>
where
    S: CustomerResourceStore,
{
    let account = ensure_account(&state, &principal).await?;
    let project_id = CustomerProjectId::parse(project_id)?;
    let deleted = state
        .store
        .delete_customer_project(&state.cluster_id, &account.account_id, &project_id)
        .await?;
    if !deleted {
        return Err(CustomerResourceError::ProjectNotFound {
            cluster_id: state.cluster_id,
            project_id,
        }
        .into());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_public_services<S>(
    State(state): State<CustomerApiState<S>>,
    Extension(principal): Extension<CustomerOidcPrincipal>,
    Path(project_id): Path<String>,
    Query(query): Query<CustomerPageQuery>,
) -> Result<Json<PublicServicesResponse>, CustomerApiError>
where
    S: CustomerResourceStore,
{
    let account = ensure_account(&state, &principal).await?;
    let project_id = CustomerProjectId::parse(project_id)?;
    let cursor = query.cursor.map(PublicServiceId::parse).transpose()?;
    let page = state
        .store
        .list_public_services(
            &state.cluster_id,
            &account.account_id,
            &project_id,
            cursor.as_ref(),
            query.limit,
        )
        .await?;
    Ok(Json(PublicServicesResponse {
        public_services: page.public_services,
        next_cursor: page.next_cursor,
    }))
}

async fn create_public_service<S>(
    State(state): State<CustomerApiState<S>>,
    Extension(principal): Extension<CustomerOidcPrincipal>,
    Path(project_id): Path<String>,
    Json(request): Json<CreatePublicServiceRequest>,
) -> Result<(StatusCode, Json<PublicServiceResponse>), CustomerApiError>
where
    S: CustomerResourceStore,
{
    let account = ensure_account(&state, &principal).await?;
    let public_service = state
        .store
        .create_public_service(CreatePublicService {
            cluster_id: state.cluster_id.clone(),
            resource_id: new_public_service_id()?,
            account_id: account.account_id,
            project_id: CustomerProjectId::parse(project_id)?,
            name: KubernetesName::parse(request.name)?,
            spec: request.spec,
            created_at: Utc::now(),
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(PublicServiceResponse { public_service }),
    ))
}

async fn get_public_service<S>(
    State(state): State<CustomerApiState<S>>,
    Extension(principal): Extension<CustomerOidcPrincipal>,
    Path((project_id, resource_id)): Path<(String, String)>,
) -> Result<Json<PublicServiceResponse>, CustomerApiError>
where
    S: CustomerResourceStore,
{
    let account = ensure_account(&state, &principal).await?;
    let project_id = CustomerProjectId::parse(project_id)?;
    let resource_id = PublicServiceId::parse(resource_id)?;
    let public_service = state
        .store
        .get_public_service(
            &state.cluster_id,
            &account.account_id,
            &project_id,
            &resource_id,
        )
        .await?
        .ok_or_else(|| CustomerResourceError::PublicServiceNotFound {
            cluster_id: state.cluster_id.clone(),
            resource_id,
        })?;
    Ok(Json(PublicServiceResponse { public_service }))
}

async fn delete_public_service<S>(
    State(state): State<CustomerApiState<S>>,
    Extension(principal): Extension<CustomerOidcPrincipal>,
    Path((project_id, resource_id)): Path<(String, String)>,
) -> Result<StatusCode, CustomerApiError>
where
    S: CustomerResourceStore,
{
    let account = ensure_account(&state, &principal).await?;
    let project_id = CustomerProjectId::parse(project_id)?;
    let resource_id = PublicServiceId::parse(resource_id)?;
    let deleted = state
        .store
        .delete_public_service(
            &state.cluster_id,
            &account.account_id,
            &project_id,
            &resource_id,
        )
        .await?;
    if !deleted {
        return Err(CustomerResourceError::PublicServiceNotFound {
            cluster_id: state.cluster_id,
            resource_id,
        }
        .into());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_desired_public_services<S>(
    State(state): State<CustomerApiState<S>>,
    Query(query): Query<ControllerDesiredResourcesQuery>,
) -> Result<Json<ControllerDesiredResourcesResponse>, CustomerApiError>
where
    S: CustomerResourceStore,
{
    match query.kind {
        ControllerDesiredResourceKind::Projects => {
            let cursor = query.cursor.map(CustomerProjectId::parse).transpose()?;
            let page = state
                .store
                .list_desired_customer_projects(&state.cluster_id, cursor.as_ref(), query.limit)
                .await?;
            Ok(Json(ControllerDesiredResourcesResponse {
                projects: page.projects,
                public_services: Vec::new(),
                next_cursor: page.next_cursor.map(String::from),
            }))
        }
        ControllerDesiredResourceKind::PublicServices => {
            let cursor = query.cursor.map(PublicServiceId::parse).transpose()?;
            let page = state
                .store
                .list_desired_public_services(&state.cluster_id, cursor.as_ref(), query.limit)
                .await?;
            Ok(Json(ControllerDesiredResourcesResponse {
                projects: Vec::new(),
                public_services: page.public_services,
                next_cursor: page.next_cursor.map(String::from),
            }))
        }
    }
}

async fn update_public_service_status<S>(
    State(state): State<CustomerApiState<S>>,
    Path(resource_id): Path<String>,
    Json(request): Json<ControllerStatusRequest>,
) -> Result<Json<PublicServiceResponse>, CustomerApiError>
where
    S: CustomerResourceStore,
{
    let public_service = state
        .store
        .update_public_service_status(
            &state.cluster_id,
            &PublicServiceId::parse(resource_id)?,
            request.expected_generation,
            request.status,
        )
        .await?;
    Ok(Json(PublicServiceResponse { public_service }))
}

async fn ensure_account<S>(
    state: &CustomerApiState<S>,
    principal: &CustomerOidcPrincipal,
) -> Result<CustomerAccount, CustomerApiError>
where
    S: CustomerResourceStore,
{
    state
        .store
        .ensure_personal_account(EnsurePersonalAccount {
            cluster_id: state.cluster_id.clone(),
            identity: KeycloakIdentity::new(&principal.issuer, &principal.subject)?,
            quota: state.default_quota,
            created_at: Utc::now(),
        })
        .await
        .map_err(Into::into)
}

const fn default_customer_page_size() -> usize {
    DEFAULT_CUSTOMER_RESOURCE_PAGE_SIZE
}

const fn max_customer_page_size() -> usize {
    MAX_CUSTOMER_RESOURCE_PAGE_SIZE
}

fn new_public_service_id() -> Result<PublicServiceId, CustomerApiError> {
    let mut entropy = [0_u8; 16];
    OsRng.try_fill_bytes(&mut entropy).map_err(|_| {
        CustomerResourceError::Store(
            "operating-system randomness is unavailable for resource creation".to_string(),
        )
    })?;
    Ok(PublicServiceId::from_entropy(entropy))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderMap, Method, Request};
    use axum::routing::get;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ipars_control_plane::InMemoryStore;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::{bearer_token_from_headers, unverified_jwt_claims};

    const ISSUER: &str = "https://accounts.example/realms/customers";
    const CONTROLLER_TOKEN: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[tokio::test]
    async fn customer_and_controller_surfaces_enforce_identity_ownership_and_isolation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (auth, idp_task) = customer_auth().await?;
        let store = Arc::new(InMemoryStore::default());
        let cluster_id = ClusterId::from_string("cluster-a");
        let customer_app = customer_router(
            store.clone(),
            cluster_id.clone(),
            auth,
            CustomerQuota::new(3, 5)?,
        );
        let owner_token = customer_token("owner", &["heteronetwork-customer"]);
        let stranger_token = customer_token("stranger", &["heteronetwork-customer"]);
        let controller_app = customer_controller_router(
            store.clone(),
            cluster_id.clone(),
            CONTROLLER_TOKEN.to_string(),
        )?;

        let created_project = call_json(
            &customer_app,
            Method::POST,
            "/v1/customer/projects",
            Some(&owner_token),
            Some(json!({"name": "games"})),
        )
        .await?;
        assert_eq!(created_project.0, StatusCode::CREATED);
        let project_id = created_project
            .1
            .pointer("/project/project_id")
            .and_then(Value::as_str)
            .ok_or("project response did not contain project_id")?
            .to_string();
        let desired_project = call_json(
            &controller_app,
            Method::GET,
            "/internal/v1/customer/public-services?kind=projects",
            Some(CONTROLLER_TOKEN),
            None,
        )
        .await?;
        assert_eq!(
            desired_project
                .1
                .get("projects")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            desired_project
                .1
                .get("public_services")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        let created_service = call_json(
            &customer_app,
            Method::POST,
            &format!("/v1/customer/projects/{project_id}/public-services"),
            Some(&owner_token),
            Some(json!({
                "name": "livekit",
                "spec": {
                    "traffic_mode": "forwarded",
                    "protocol": "UDP",
                    "public_port": 7882,
                    "backend_service": "livekit",
                    "backend_port": 7882,
                    "ingress_replicas": 2
                }
            })),
        )
        .await?;
        assert_eq!(created_service.0, StatusCode::CREATED);
        let resource_id = created_service
            .1
            .pointer("/public_service/resource_id")
            .and_then(Value::as_str)
            .ok_or("public service response did not contain resource_id")?
            .to_string();

        let cross_account = call_json(
            &customer_app,
            Method::GET,
            &format!("/v1/customer/projects/{project_id}/public-services"),
            Some(&stranger_token),
            None,
        )
        .await?;
        assert_eq!(cross_account.0, StatusCode::NOT_FOUND);
        assert_eq!(
            call_json(
                &customer_app,
                Method::GET,
                &format!("/v1/customer/projects/{project_id}"),
                Some(&stranger_token),
                None,
            )
            .await?
            .0,
            StatusCode::NOT_FOUND
        );

        let missing_role = call_json(
            &customer_app,
            Method::GET,
            "/v1/customer/session",
            Some(&customer_token("viewer", &["offline_access"])),
            None,
        )
        .await?;
        assert_eq!(missing_role.0, StatusCode::FORBIDDEN);
        assert_eq!(
            call_json(
                &customer_app,
                Method::GET,
                "/internal/v1/customer/public-services",
                Some(CONTROLLER_TOKEN),
                None,
            )
            .await?
            .0,
            StatusCode::NOT_FOUND
        );

        assert_eq!(
            call_json(
                &controller_app,
                Method::GET,
                "/v1/customer/session",
                Some(&owner_token),
                None,
            )
            .await?
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call_json(
                &controller_app,
                Method::GET,
                "/internal/v1/customer/public-services",
                None,
                None,
            )
            .await?
            .0,
            StatusCode::UNAUTHORIZED
        );
        let desired_projects = call_json(
            &controller_app,
            Method::GET,
            "/internal/v1/customer/public-services?kind=projects",
            Some(CONTROLLER_TOKEN),
            None,
        )
        .await?;
        assert_eq!(desired_projects.0, StatusCode::OK);
        assert_eq!(
            desired_projects
                .1
                .get("projects")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        let desired_services = call_json(
            &controller_app,
            Method::GET,
            "/internal/v1/customer/public-services?kind=public_services",
            Some(CONTROLLER_TOKEN),
            None,
        )
        .await?;
        assert_eq!(
            desired_services
                .1
                .get("public_services")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );

        let status = call_json(
            &controller_app,
            Method::PUT,
            &format!("/internal/v1/customer/public-services/{resource_id}/status"),
            Some(CONTROLLER_TOKEN),
            Some(json!({
                "expected_generation": 1,
                "status": {
                    "phase": "ready",
                    "public_addresses": [{
                        "host": "203.0.113.10",
                        "port": 7882
                    }],
                    "message": null,
                    "observed_generation": 1,
                    "observed_at": Utc::now()
                }
            })),
        )
        .await?;
        assert_eq!(status.0, StatusCode::OK);
        assert_eq!(
            status
                .1
                .pointer("/public_service/status/phase")
                .and_then(Value::as_str),
            Some("ready")
        );
        assert_eq!(
            call_json(
                &customer_app,
                Method::DELETE,
                &format!("/v1/customer/projects/{project_id}/public-services/{resource_id}"),
                Some(&owner_token),
                None,
            )
            .await?
            .0,
            StatusCode::NO_CONTENT
        );
        let recreated_service = call_json(
            &customer_app,
            Method::POST,
            &format!("/v1/customer/projects/{project_id}/public-services"),
            Some(&owner_token),
            Some(json!({
                "name": "livekit",
                "spec": {
                    "traffic_mode": "forwarded",
                    "protocol": "UDP",
                    "public_port": 7882,
                    "backend_service": "livekit",
                    "backend_port": 7882,
                    "ingress_replicas": 2
                }
            })),
        )
        .await?;
        assert_eq!(recreated_service.0, StatusCode::CREATED);
        let replacement_resource_id = recreated_service
            .1
            .pointer("/public_service/resource_id")
            .and_then(Value::as_str)
            .ok_or("replacement response did not contain resource_id")?;
        assert_ne!(replacement_resource_id, resource_id);
        assert_eq!(
            call_json(
                &controller_app,
                Method::PUT,
                &format!("/internal/v1/customer/public-services/{resource_id}/status"),
                Some(CONTROLLER_TOKEN),
                Some(json!({
                    "expected_generation": 1,
                    "status": {
                        "phase": "ready",
                        "public_addresses": [{
                            "host": "203.0.113.10",
                            "port": 7882
                        }],
                        "message": null,
                        "observed_generation": 1,
                        "observed_at": Utc::now()
                    }
                })),
            )
            .await?
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call_json(
                &customer_app,
                Method::DELETE,
                &format!("/v1/customer/projects/{project_id}"),
                Some(&owner_token),
                None,
            )
            .await?
            .0,
            StatusCode::NO_CONTENT
        );
        let desired_projects = call_json(
            &controller_app,
            Method::GET,
            "/internal/v1/customer/public-services?kind=projects",
            Some(CONTROLLER_TOKEN),
            None,
        )
        .await?;
        assert_eq!(
            desired_projects
                .1
                .get("projects")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        let desired_services = call_json(
            &controller_app,
            Method::GET,
            "/internal/v1/customer/public-services?kind=public_services",
            Some(CONTROLLER_TOKEN),
            None,
        )
        .await?;
        assert_eq!(
            desired_services
                .1
                .get("public_services")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        idp_task.abort();
        Ok(())
    }

    async fn customer_auth(
    ) -> Result<(CustomerAuthConfig, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let app = Router::new().route(
                "/realms/customers/protocol/openid-connect/userinfo",
                get(|headers: HeaderMap| async move {
                    let subject = bearer_token_from_headers(&headers)
                        .and_then(unverified_jwt_claims)
                        .and_then(|claims| {
                            claims
                                .get("sub")
                                .and_then(Value::as_str)
                                .map(str::to_string)
                        })
                        .unwrap_or_default();
                    Json(json!({
                        "sub": subject,
                        "email": format!("{subject}@example.com")
                    }))
                }),
            );
            let _ = axum::serve(listener, app).await;
        });
        let auth = CustomerAuthConfig::new(
            ISSUER.to_string(),
            "heteronetwork-customer-console".to_string(),
            "heteronetwork-customer-api".to_string(),
            None,
            Some(format!("http://{address}/realms/customers")),
            "openid profile email".to_string(),
        )?;
        Ok((auth, task))
    }

    fn customer_token(subject: &str, roles: &[&str]) -> String {
        format!(
            "e30.{}.signature",
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "iss": ISSUER,
                    "sub": subject,
                    "azp": "heteronetwork-customer-console",
                    "aud": ["heteronetwork-customer-api"],
                    "realm_access": {"roles": roles}
                }))
                .unwrap_or_default()
            )
        )
    }

    async fn call_json(
        app: &Router,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(body) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&body)?)
            }
            None => Body::empty(),
        };
        let response = app.clone().oneshot(builder.body(body)?).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), MAX_CUSTOMER_RESOURCE_REQUEST_BYTES).await?;
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "HTTP {status} returned a non-JSON body {:?}: {error}",
                        String::from_utf8_lossy(&bytes)
                    ),
                )
            })?
        };
        Ok((status, body))
    }
}
