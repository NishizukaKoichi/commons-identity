//! Reference HTTP service for the Commons Identity Developer Preview.
//!
//! The server deliberately defaults to a local interoperability lab. A real
//! operator must replace demo enrollment and persist operator state.

mod discovery;
mod jws;
mod model;
mod oid4vci;
mod oid4vp;
mod operations;
mod state;

use std::sync::Arc;

use axum::{
    Json, Router,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http::HeaderName;
use serde::Serialize;
use serde_json::json;
use tower_http::{
    limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer, trace::TraceLayer,
};

pub use jws::{
    sign_request_object, sign_request_object_with_kid, verify_request_object,
    verify_request_object_with_kid,
};
pub use model::{
    AuthorizationRequestObject, CiKeyProof, CredentialRequest, CredentialResponse,
    DeviceRevocationRequest, EnrollmentRequest, EnrollmentResponse, GovernanceApproval,
    OperatorExportRequest, OperatorImportRequest, OperatorImportResponse, PresentationRequestInput,
    PresentationRequestResponse, ServiceConfig, SignedCommunityProfile, TokenRequest,
    TokenResponse, VpToken,
};
pub use operations::{operator_export_action_hash, operator_import_action_hash};
pub use state::AppState;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    description: String,
}

impl ApiError {
    pub fn invalid(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            description: description.into(),
        }
    }

    pub fn unauthorized(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_token",
            description: description.into(),
        }
    }

    pub fn not_found(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            description: description.into(),
        }
    }

    pub fn conflict(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "invalid_request",
            description: description.into(),
        }
    }

    pub fn internal(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "server_error",
            description: description.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(json!({
                "error": self.code,
                "error_description": self.description,
            })),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.description)
    }
}

impl std::error::Error for ApiError {}

impl From<commons_identity_core::CommonsError> for ApiError {
    fn from(value: commons_identity_core::CommonsError) -> Self {
        match value {
            commons_identity_core::CommonsError::Unauthorized(message) => {
                Self::unauthorized(message)
            }
            commons_identity_core::CommonsError::NotFound(message) => Self::not_found(message),
            commons_identity_core::CommonsError::Replay => {
                Self::conflict("request has already been consumed")
            }
            other => Self::invalid(other.to_string()),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(value: serde_json::Error) -> Self {
        Self::invalid(value.to_string())
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(discovery::health))
        .route(
            "/.well-known/commons-identity",
            get(discovery::community_profile),
        )
        .route(
            "/.well-known/openid-credential-issuer",
            get(discovery::credential_issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(discovery::authorization_server_metadata),
        )
        .route("/contexts/v1", get(discovery::context_v1))
        .route("/contexts/v1.jsonld", get(discovery::context_v1))
        .route("/schemas/{schema_id}", get(discovery::schema))
        .route("/policies/{policy_hash}", get(discovery::policy))
        .route("/status/{status_list_id}", get(discovery::status_list))
        .route(
            "/audit/checkpoints/{sequence}",
            get(discovery::audit_checkpoint),
        )
        .route("/oid4vci/enroll", post(oid4vci::enroll))
        .route("/oid4vci/offers/{offer_id}", get(oid4vci::credential_offer))
        .route("/oid4vci/token", post(oid4vci::token))
        .route("/oid4vci/nonce", post(oid4vci::nonce))
        .route("/oid4vci/credential", post(oid4vci::credential))
        .route("/oid4vp/requests", post(oid4vp::create_request))
        .route(
            "/oid4vp/requests/{state}",
            get(oid4vp::get_request).post(oid4vp::post_request),
        )
        .route("/oid4vp/direct_post", post(oid4vp::direct_post))
        .route("/ci/v1/device/revoke", post(operations::revoke_device))
        .route("/ci/v1/operator/export", post(operations::export_operator))
        .route("/ci/v1/operator/import", post(operations::import_operator))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(512 * 1024))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(TraceLayer::new_for_http())
}

pub(crate) fn no_store_json<T: Serialize>(value: T) -> Result<Response, ApiError> {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use commons_identity_core::SigningKeyMaterial;
    use time::OffsetDateTime;

    use crate::{AppState, ServiceConfig};

    pub(crate) fn test_state() -> std::sync::Arc<AppState> {
        let governance_controllers = (1_u8..=5)
            .map(|index| {
                let key = SigningKeyMaterial::from_secret([index; 32]);
                (key.did_key(), key.public_key_multibase())
            })
            .collect::<BTreeMap<_, _>>();
        AppState::new(
            ServiceConfig {
                public_base_url: "http://127.0.0.1:8787".into(),
                community_id: "did:webvh:test-community:identity.example".into(),
                community_name: "Commons Identity Test Community".into(),
                operator_id: "did:webvh:test-operator:operator.example".into(),
                verifier_id: "did:webvh:test-verifier:verifier.example".into(),
                policy_hash: "sha256-test-policy".into(),
                mirrors: vec![
                    "https://mirror-a.example".into(),
                    "https://mirror-b.example".into(),
                    "https://mirror-c.example".into(),
                ],
                governance_controllers,
                enrollment_code: "test-enrollment-code".to_string().into(),
                admin_token: "test-admin-token-at-least-24-characters".to_string().into(),
                expose_demo_codes: true,
                ephemeral_developer_preview: true,
            },
            OffsetDateTime::now_utc(),
        )
        .expect("test service configuration must be valid")
    }
}
