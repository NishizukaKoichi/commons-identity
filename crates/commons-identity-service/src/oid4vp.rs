use std::sync::Arc;

use axum::{
    Form, Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderValue, header},
    response::Response,
};
use commons_identity_core::{
    CiRequest, Linkability, Presentation, StatusPurpose, crypto::random_urlsafe,
    status::StatusAssessment,
};
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use crate::{
    ApiError,
    jws::sign_request_object_with_kid,
    model::{
        AuthorizationRequestObject, DcqlClaimQuery, DcqlCredentialQuery, DcqlQuery, DirectPostForm,
        DirectPostResponse, PendingPresentationRequest, PresentationRequestInput,
        PresentationRequestResponse, VpToken,
    },
    no_store_json,
    state::{AppState, trim_base},
};

pub(crate) async fn create_request(
    State(state): State<Arc<AppState>>,
    Json(input): Json<PresentationRequestInput>,
) -> Result<Response, ApiError> {
    let now = OffsetDateTime::now_utc();
    let request = CiRequest::new(
        input.purpose,
        input.requested_claims,
        input.retention_seconds,
        input.onward_sharing,
        Linkability::Community,
        None,
        state.config.verifier_id.clone(),
        now,
    )?;
    let state_value = random_urlsafe(&mut OsRng, 32);
    let base = trim_base(&state.config.public_base_url);
    let dcql = DcqlQuery {
        credentials: vec![DcqlCredentialQuery {
            id: "membership".into(),
            format: "application/vc".into(),
            meta: json!({
                "type_values": [["VerifiableCredential", "CommunityMembershipCredential"]],
                "cryptosuite": "eddsa-jcs-2022"
            }),
            claims: request
                .requested_claims
                .iter()
                .map(|claim| DcqlClaimQuery {
                    path: vec!["credentialSubject".into(), claim.clone()],
                })
                .collect(),
        }],
    };
    let object = AuthorizationRequestObject {
        iss: state.config.verifier_id.clone(),
        aud: "https://self-issued.me/v2".into(),
        iat: now.unix_timestamp(),
        exp: (now + Duration::minutes(5)).unix_timestamp(),
        client_id: format!("decentralized_identifier:{}", state.config.verifier_id),
        response_type: "vp_token".into(),
        response_mode: "direct_post".into(),
        response_uri: format!("{base}/oid4vp/direct_post"),
        nonce: request.nonce.clone(),
        state: state_value.clone(),
        dcql_query: dcql,
        ci_request: request,
        client_metadata: json!({
            "vp_formats_supported": {
                "application/vp": {
                    "cryptosuites_supported": ["eddsa-jcs-2022"]
                }
            },
            "ci_request_required": true
        }),
    };
    object.validate_ci_alignment(now)?;
    let kid = format!(
        "{}#{}",
        state.config.verifier_id,
        state.verifier_public_key()
    );
    let request_jwt = sign_request_object_with_kid(&object, &state.verifier_key, &kid)?;
    let mut requests = state
        .presentation_requests
        .lock()
        .map_err(|_| ApiError::internal("presentation request lock poisoned"))?;
    requests.retain(|_, pending| !pending.consumed && pending.object.exp > now.unix_timestamp());
    if requests.len() >= crate::state::MAX_EPHEMERAL_ITEMS {
        return Err(ApiError::conflict("too many pending presentation requests"));
    }
    requests.insert(
        state_value.clone(),
        PendingPresentationRequest {
            object,
            request_jwt: request_jwt.clone(),
            consumed: false,
        },
    );
    drop(requests);
    no_store_json(PresentationRequestResponse {
        request_id: state_value.clone(),
        request_uri: format!("{base}/oid4vp/requests/{state_value}"),
        request: request_jwt,
        expires_in: 300,
    })
}

pub(crate) async fn get_request(
    State(state): State<Arc<AppState>>,
    Path(state_value): Path<String>,
) -> Result<Response, ApiError> {
    request_object_response(&state, &state_value)
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RequestUriForm {
    wallet_nonce: Option<String>,
}

pub(crate) async fn post_request(
    State(state): State<Arc<AppState>>,
    Path(state_value): Path<String>,
    Form(form): Form<RequestUriForm>,
) -> Result<Response, ApiError> {
    if form.wallet_nonce.is_some() {
        return Err(ApiError::invalid(
            "wallet_nonce negotiation is not implemented by this Developer Preview",
        ));
    }
    request_object_response(&state, &state_value)
}

fn request_object_response(state: &AppState, state_value: &str) -> Result<Response, ApiError> {
    let requests = state
        .presentation_requests
        .lock()
        .map_err(|_| ApiError::internal("presentation request lock poisoned"))?;
    let request = requests
        .get(state_value)
        .ok_or_else(|| ApiError::not_found("presentation request does not exist"))?;
    if request.consumed || OffsetDateTime::now_utc().unix_timestamp() >= request.object.exp {
        return Err(ApiError::not_found(
            "presentation request was consumed or expired",
        ));
    }
    let mut response = Response::new(Body::from(request.request_jwt.clone()));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/oauth-authz-req+jwt"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(crate) async fn direct_post(
    State(state): State<Arc<AppState>>,
    Form(form): Form<DirectPostForm>,
) -> Result<Response, ApiError> {
    let now = OffsetDateTime::now_utc();
    let mut requests = state
        .presentation_requests
        .lock()
        .map_err(|_| ApiError::internal("presentation request lock poisoned"))?;
    let pending = requests
        .get_mut(&form.state)
        .ok_or_else(|| ApiError::invalid("unknown authorization response state"))?;
    if pending.consumed {
        return Err(ApiError::conflict(
            "authorization response was already consumed",
        ));
    }
    pending.object.validate_ci_alignment(now)?;
    let token: VpToken = serde_json::from_str(&form.vp_token)?;
    if token.membership.len() != 1 {
        return Err(ApiError::invalid(
            "membership DCQL response must contain exactly one presentation",
        ));
    }
    let presentation = &token.membership[0];
    presentation.verify_ci_core(&pending.object.ci_request, &state.issuer_public_key(), now)?;
    verify_current_status(&state, presentation, now)?;
    let presentation_hash = presentation.hash()?;
    pending.consumed = true;
    no_store_json(DirectPostResponse {
        result: "verified".into(),
        presentation_hash,
    })
}

fn verify_current_status(
    state: &AppState,
    presentation: &Presentation,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    let credential = presentation
        .verifiable_credential
        .first()
        .ok_or_else(|| ApiError::invalid("presentation contains no credential"))?;
    if credential.issuer != state.config.community_id {
        return Err(ApiError::unauthorized(
            "credential issuer is not this Community Authority",
        ));
    }
    let mut saw_revocation = false;
    let mut saw_suspension = false;
    for reference in &credential.credential_status {
        let index = reference
            .status_list_index
            .parse::<usize>()
            .map_err(|_| ApiError::invalid("statusListIndex is invalid"))?;
        let assessment = match reference.status_purpose.as_str() {
            "revocation" => {
                saw_revocation = true;
                let list = state
                    .revocation_status
                    .read()
                    .map_err(|_| ApiError::internal("status lock poisoned"))?;
                if reference.status_list_credential != list.id {
                    return Err(ApiError::unauthorized(
                        "credential points to an unexpected revocation list",
                    ));
                }
                list.assess(index, Duration::hours(24), now)?
            }
            "suspension" => {
                saw_suspension = true;
                let list = state
                    .suspension_status
                    .read()
                    .map_err(|_| ApiError::internal("status lock poisoned"))?;
                if reference.status_list_credential != list.id {
                    return Err(ApiError::unauthorized(
                        "credential points to an unexpected suspension list",
                    ));
                }
                list.assess(index, Duration::hours(24), now)?
            }
            _ => return Err(ApiError::invalid("unsupported status purpose")),
        };
        match assessment {
            StatusAssessment::Active { .. } => {}
            StatusAssessment::Listed {
                purpose: StatusPurpose::Revocation,
                ..
            } => return Err(ApiError::unauthorized("credential has been revoked")),
            StatusAssessment::Listed {
                purpose: StatusPurpose::Suspension,
                ..
            } => return Err(ApiError::unauthorized("credential is suspended")),
            StatusAssessment::CurrentStatusUnknown { .. } => {
                return Err(ApiError::unauthorized(
                    "credential status is stale; current status is unknown",
                ));
            }
        }
    }
    if !saw_revocation || !saw_suspension {
        return Err(ApiError::unauthorized(
            "CI-Core access requires both revocation and suspension status entries",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::Request};
    use tower::ServiceExt as _;

    use super::*;
    use crate::{app, verify_request_object_with_kid};
    use commons_identity_core::PresentationPurpose;

    #[tokio::test]
    async fn request_object_is_signed_bound_and_retrievable() {
        let state = crate::tests::test_state();
        let body = serde_json::to_vec(&PresentationRequestInput {
            purpose: PresentationPurpose {
                code: "community_document_access".into(),
                display: "Access the research archive".into(),
            },
            requested_claims: vec!["community".into(), "membership".into(), "scope".into()],
            retention_seconds: 300,
            onward_sharing: false,
        })
        .unwrap();
        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oid4vp/requests")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: PresentationRequestResponse = serde_json::from_slice(&bytes).unwrap();
        let expected_kid = format!(
            "{}#{}",
            state.config.verifier_id,
            state.verifier_public_key()
        );
        let object: AuthorizationRequestObject = verify_request_object_with_kid(
            &created.request,
            &state.verifier_public_key(),
            Some(&expected_kid),
        )
        .unwrap();
        object
            .validate_ci_alignment(OffsetDateTime::now_utc())
            .unwrap();
        let uri = url::Url::parse(&created.request_uri).unwrap();
        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri(uri.path())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/oauth-authz-req+jwt"
        );
    }

    #[test]
    fn alignment_fails_if_ci_request_and_dcql_diverge() {
        let now = OffsetDateTime::now_utc();
        let request = CiRequest::new(
            commons_identity_core::PresentationPurpose {
                code: "test".into(),
                display: "Test".into(),
            },
            vec!["membership".into()],
            0,
            false,
            Linkability::Community,
            None,
            "did:webvh:verifier:example",
            now,
        )
        .unwrap();
        let mut object = AuthorizationRequestObject {
            iss: "did:webvh:verifier:example".into(),
            aud: "https://self-issued.me/v2".into(),
            iat: now.unix_timestamp(),
            exp: (now + Duration::minutes(5)).unix_timestamp(),
            client_id: "decentralized_identifier:did:webvh:verifier:example".into(),
            response_type: "vp_token".into(),
            response_mode: "direct_post".into(),
            response_uri: "https://verifier.example/post".into(),
            nonce: request.nonce.clone(),
            state: "state-with-at-least-128-bits-of-entropy".into(),
            dcql_query: DcqlQuery {
                credentials: vec![DcqlCredentialQuery {
                    id: "membership".into(),
                    format: "application/vc".into(),
                    meta: json!({"cryptosuite": "eddsa-jcs-2022"}),
                    claims: vec![DcqlClaimQuery {
                        path: vec!["credentialSubject".into(), "role".into()],
                    }],
                }],
            },
            ci_request: request,
            client_metadata: json!({"ci_request_required": true}),
        };
        assert!(object.validate_ci_alignment(now).is_err());
        object.dcql_query.credentials[0].claims[0].path[1] = "membership".into();
        object.validate_ci_alignment(now).unwrap();
    }
}
