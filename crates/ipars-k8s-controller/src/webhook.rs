use axum::{routing::get, routing::post, Json, Router};
use ipars_k8s_controller::direct_pod_patch;
use k8s_openapi::api::core::v1::Pod;
use kube::core::{
    admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
    DynamicObject,
};

pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/mutate-v1-pod", post(mutate_pod))
}

async fn mutate_pod(
    Json(review): Json<AdmissionReview<Pod>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let request: AdmissionRequest<Pod> = match review.try_into() {
        Ok(request) => request,
        Err(error) => {
            return Json(
                AdmissionResponse::invalid(format!("invalid AdmissionReview: {error}"))
                    .into_review(),
            );
        }
    };

    let mut response = AdmissionResponse::from(&request);
    response = match request.object.as_ref() {
        Some(pod) => match direct_pod_patch(pod) {
            Ok(patch) if patch.0.is_empty() => response,
            Ok(patch) => match response.with_patch(patch) {
                Ok(response) => response,
                Err(error) => AdmissionResponse::from(&request)
                    .deny(format!("failed to encode Pod mutation: {error}")),
            },
            Err(error) => response.deny(error),
        },
        None => response.deny("Pod admission request did not include an object"),
    };

    Json(response.into_review())
}
