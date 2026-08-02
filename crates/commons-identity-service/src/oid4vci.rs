use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use commons_identity_core::{
    CredentialKind, CredentialStatusReference, UnsignedCredential, credential::HolderBinding,
    crypto::random_urlsafe,
};
use rand::{Rng, rngs::OsRng};
use serde_json::json;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    ApiError,
    model::{
        AccessGrant, CredentialRequest, CredentialResponse, CredentialResult, EnrollmentRequest,
        EnrollmentResponse, IssuedDevice, PRE_AUTHORIZED_GRANT, PendingOffer, TokenRequest,
        TokenResponse, credential_kind, offer_hash,
    },
    no_store_json,
    state::{AppState, OfferLocator, trim_base},
};

pub(crate) async fn enroll(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, ApiError> {
    if !constant_time_eq(&request.enrollment_code, &state.config.enrollment_code) {
        return Err(ApiError::unauthorized("invalid enrollment code"));
    }
    credential_kind(&request.credential_configuration_id)?;
    if request.member_reference.trim().is_empty() || request.member_reference.len() > 120 {
        return Err(ApiError::invalid("member reference is invalid"));
    }
    validate_ed25519_multikey(&request.holder_public_key_multibase)?;

    let mut rng = OsRng;
    let pre_authorized_code = random_urlsafe(&mut rng, 32);
    let tx_code = format!("{:06}", rng.gen_range(0..1_000_000_u32));
    let offer_id = random_urlsafe(&mut rng, 24);
    let now = OffsetDateTime::now_utc();
    let pending = PendingOffer {
        credential_configuration_id: request.credential_configuration_id.clone(),
        member_reference: request.member_reference,
        persona_device_id: request.persona_device_id,
        holder_public_key_multibase: request.holder_public_key_multibase,
        role: request.role,
        tx_code_hash: offer_hash(&tx_code),
        failed_tx_code_attempts: 0,
        expires_at: now + Duration::minutes(5),
    };
    {
        let mut offers = state
            .offers
            .lock()
            .map_err(|_| ApiError::internal("offer lock poisoned"))?;
        offers.retain(|_, offer| now < offer.expires_at);
        if offers.len() >= crate::state::MAX_EPHEMERAL_ITEMS {
            return Err(ApiError::conflict("too many pending credential offers"));
        }
        offers.insert(pre_authorized_code.clone(), pending);
    }

    let base = trim_base(&state.config.public_base_url);
    let offer = json!({
        "credential_issuer": base,
        "credential_configuration_ids": [request.credential_configuration_id],
        "grants": {
            PRE_AUTHORIZED_GRANT: {
                "pre-authorized_code": pre_authorized_code,
                "tx_code": {
                    "input_mode": "numeric",
                    "length": 6,
                    "description": "Obtain this one-time code through the community's separate enrollment channel."
                }
            }
        }
    });
    {
        let mut locators = state
            .offer_locators
            .lock()
            .map_err(|_| ApiError::internal("offer locator lock poisoned"))?;
        locators.retain(|_, locator| now < locator.expires_at);
        if locators.len() >= crate::state::MAX_EPHEMERAL_ITEMS {
            return Err(ApiError::conflict(
                "too many pending credential offer locators",
            ));
        }
        locators.insert(
            offer_id.clone(),
            OfferLocator {
                pre_authorized_code,
                offer: offer.clone(),
                expires_at: now + Duration::minutes(5),
            },
        );
    }
    Ok(Json(EnrollmentResponse {
        credential_offer_uri: format!("{base}/oid4vci/offers/{offer_id}"),
        credential_offer: offer,
        development_out_of_band_tx_code: state.config.expose_demo_codes.then_some(tx_code),
        expires_in: 300,
    }))
}

pub(crate) async fn credential_offer(
    State(state): State<Arc<AppState>>,
    Path(offer_id): Path<String>,
) -> Result<Response, ApiError> {
    let mut locators = state
        .offer_locators
        .lock()
        .map_err(|_| ApiError::internal("offer locator lock poisoned"))?;
    let now = OffsetDateTime::now_utc();
    locators.retain(|_, locator| now < locator.expires_at);
    let locator = locators
        .get(&offer_id)
        .ok_or_else(|| ApiError::not_found("credential offer does not exist"))?;
    if !state
        .offers
        .lock()
        .map_err(|_| ApiError::internal("offer lock poisoned"))?
        .contains_key(&locator.pre_authorized_code)
    {
        return Err(ApiError::not_found(
            "credential offer has expired or was used",
        ));
    }
    let mut response = Json(locator.offer.clone()).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(crate) async fn token(
    State(state): State<Arc<AppState>>,
    Form(request): Form<TokenRequest>,
) -> Result<Response, ApiError> {
    if request.grant_type != PRE_AUTHORIZED_GRANT {
        return Err(ApiError::invalid("unsupported grant_type"));
    }
    let mut offers = state
        .offers
        .lock()
        .map_err(|_| ApiError::internal("offer lock poisoned"))?;
    let now = OffsetDateTime::now_utc();
    offers.retain(|_, offer| now < offer.expires_at);
    let pending = offers
        .get(&request.pre_authorized_code)
        .ok_or_else(|| ApiError::invalid("pre-authorized code is invalid or already used"))?;
    if now >= pending.expires_at {
        offers.remove(&request.pre_authorized_code);
        return Err(ApiError::invalid("pre-authorized code has expired"));
    }
    let tx_code = request
        .tx_code
        .as_deref()
        .ok_or_else(|| ApiError::invalid("tx_code is required"))?;
    if !constant_time_eq(&offer_hash(tx_code), &pending.tx_code_hash) {
        let pending = offers
            .get_mut(&request.pre_authorized_code)
            .expect("offer was checked above");
        pending.failed_tx_code_attempts = pending.failed_tx_code_attempts.saturating_add(1);
        let locked = pending.failed_tx_code_attempts >= 5;
        if locked {
            offers.remove(&request.pre_authorized_code);
        }
        return Err(ApiError::invalid(if locked {
            "tx_code is invalid; offer is locked after five failed attempts"
        } else {
            "tx_code is invalid"
        }));
    }
    let pending = offers
        .remove(&request.pre_authorized_code)
        .expect("offer was checked above");
    let mut rng = OsRng;
    let access_token = random_urlsafe(&mut rng, 32);
    let c_nonce = random_urlsafe(&mut rng, 32);
    let mut grants = state
        .access_grants
        .lock()
        .map_err(|_| ApiError::internal("access grant lock poisoned"))?;
    grants.retain(|_, grant| now < grant.expires_at);
    if grants.len() >= crate::state::MAX_EPHEMERAL_ITEMS {
        return Err(ApiError::conflict("too many pending access grants"));
    }
    grants.insert(
        access_token.clone(),
        AccessGrant {
            offer: pending,
            c_nonce: c_nonce.clone(),
            expires_at: now + Duration::minutes(5),
        },
    );
    drop(grants);
    no_store_json(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 300,
        c_nonce,
    })
}

pub(crate) async fn nonce(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let c_nonce = random_urlsafe(&mut OsRng, 32);
    let now = OffsetDateTime::now_utc();
    let mut nonces = state
        .public_nonces
        .lock()
        .map_err(|_| ApiError::internal("nonce lock poisoned"))?;
    nonces.retain(|_, expires_at| now < *expires_at);
    if nonces.len() >= crate::state::MAX_EPHEMERAL_ITEMS {
        return Err(ApiError::conflict("too many pending credential nonces"));
    }
    nonces.insert(c_nonce.clone(), now + Duration::minutes(5));
    drop(nonces);
    no_store_json(json!({"c_nonce": c_nonce}))
}

pub(crate) async fn credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CredentialRequest>,
) -> Result<Response, ApiError> {
    let access_token = bearer_token(&headers)?;
    let grant = state
        .access_grants
        .lock()
        .map_err(|_| ApiError::internal("access grant lock poisoned"))?
        .remove(access_token)
        .ok_or_else(|| ApiError::unauthorized("access token is invalid or already used"))?;
    let now = OffsetDateTime::now_utc();
    if now >= grant.expires_at {
        return Err(ApiError::unauthorized("access token has expired"));
    }
    if request.credential_configuration_id != grant.offer.credential_configuration_id {
        return Err(ApiError::invalid(
            "credential configuration does not match authorization",
        ));
    }
    let proof_nonce = request.proof.payload.c_nonce.clone();
    let nonce_is_valid = if proof_nonce == grant.c_nonce {
        true
    } else {
        state
            .public_nonces
            .lock()
            .map_err(|_| ApiError::internal("nonce lock poisoned"))?
            .remove(&proof_nonce)
            .is_some_and(|expires_at| now < expires_at)
    };
    if !nonce_is_valid {
        return Err(ApiError::unauthorized("c_nonce is invalid or expired"));
    }
    request
        .proof
        .verify(&proof_nonce, trim_base(&state.config.public_base_url), now)?;
    if request.proof.payload.persona_device_id != grant.offer.persona_device_id
        || request.proof.payload.public_key_multibase != grant.offer.holder_public_key_multibase
    {
        return Err(ApiError::unauthorized(
            "proof key or persona-scoped device does not match enrollment",
        ));
    }
    let kind = credential_kind(&request.credential_configuration_id)?;
    let mut registry = state
        .issued_devices
        .lock()
        .map_err(|_| ApiError::internal("member registry lock poisoned"))?;
    validate_registry_insertion(&registry, &grant.offer)?;
    let revocation_index = state
        .revocation_status
        .write()
        .map_err(|_| ApiError::internal("status lock poisoned"))?
        .allocate_random()?;
    let suspension_index = state
        .suspension_status
        .write()
        .map_err(|_| ApiError::internal("status lock poisoned"))?
        .allocate_random()?;
    let credential = issue_credential(
        &state,
        &grant.offer,
        kind,
        revocation_index,
        suspension_index,
        now,
    )?;
    registry
        .entry(grant.offer.persona_device_id)
        .or_default()
        .push(IssuedDevice {
            member_reference: grant.offer.member_reference,
            persona_device_id: grant.offer.persona_device_id,
            public_key_multibase: grant.offer.holder_public_key_multibase,
            revocation_index,
            suspension_index,
            active: true,
        });
    drop(registry);
    no_store_json(CredentialResponse {
        format: "application/vc".into(),
        credentials: vec![CredentialResult { credential }],
    })
}

fn validate_registry_insertion(
    registry: &HashMap<Uuid, Vec<IssuedDevice>>,
    offer: &PendingOffer,
) -> Result<(), ApiError> {
    const MAX_CREDENTIAL_INSTANCES_PER_DEVICE: usize = 64;
    const MAX_ISSUED_CREDENTIAL_INSTANCES: usize = 50_000;

    if registry.len() >= crate::state::MAX_ISSUED_PERSONA_DEVICES
        && !registry.contains_key(&offer.persona_device_id)
    {
        return Err(ApiError::conflict(
            "ephemeral issued-device registry capacity reached",
        ));
    }
    if registry.values().map(Vec::len).sum::<usize>() >= MAX_ISSUED_CREDENTIAL_INSTANCES {
        return Err(ApiError::conflict(
            "ephemeral credential-instance registry capacity reached",
        ));
    }
    if let Some(existing) = registry.get(&offer.persona_device_id) {
        if existing.len() >= MAX_CREDENTIAL_INSTANCES_PER_DEVICE {
            return Err(ApiError::conflict(
                "persona-scoped device credential-instance capacity reached",
            ));
        }
        if existing.iter().any(|instance| {
            instance.member_reference != offer.member_reference
                || instance.public_key_multibase != offer.holder_public_key_multibase
        }) {
            return Err(ApiError::conflict(
                "persona-scoped device identifier cannot change member or holder key",
            ));
        }
    }
    if registry.iter().any(|(device_id, instances)| {
        *device_id != offer.persona_device_id
            && instances
                .iter()
                .any(|instance| instance.public_key_multibase == offer.holder_public_key_multibase)
    }) {
        return Err(ApiError::conflict(
            "a holder key cannot be reused across persona-scoped devices",
        ));
    }
    Ok(())
}

fn issue_credential(
    state: &AppState,
    offer: &PendingOffer,
    kind: CredentialKind,
    revocation_index: usize,
    suspension_index: usize,
    now: OffsetDateTime,
) -> Result<commons_identity_core::VerifiableCredential, ApiError> {
    let mut subject = BTreeMap::new();
    subject.insert("community".into(), json!(state.config.community_id));
    subject.insert("policyHash".into(), json!(state.config.policy_hash));
    let valid_for = match kind {
        CredentialKind::CommunityMembershipCredential => {
            subject.insert("membership".into(), json!("active"));
            subject.insert("scope".into(), json!(["community:enter"]));
            Duration::days(90)
        }
        CredentialKind::CommunityRoleCredential => {
            let role = offer
                .role
                .as_deref()
                .ok_or_else(|| ApiError::invalid("role enrollment requires a role"))?;
            subject.insert("role".into(), json!(role));
            subject.insert("scope".into(), json!([format!("role:{role}")]));
            Duration::days(30)
        }
        _ => return Err(ApiError::invalid("unsupported credential kind")),
    };
    let valid_from = format_time(now)?;
    let valid_until = format_time(now + valid_for)?;
    let base = trim_base(&state.config.public_base_url);
    let revocation = CredentialStatusReference::bitstring(
        format!("{base}/status/revocation-1"),
        revocation_index,
        "revocation",
    );
    let suspension = CredentialStatusReference::bitstring(
        format!("{base}/status/suspension-1"),
        suspension_index,
        "suspension",
    );
    let mut unsigned = UnsignedCredential::new(
        kind,
        state.config.community_id.clone(),
        valid_from.clone(),
        valid_until,
        subject,
        HolderBinding::multikey(offer.holder_public_key_multibase.clone()),
        Some(revocation),
    );
    unsigned.credential_status.push(suspension);
    unsigned
        .issue(&state.issuer_key, &valid_from)
        .map_err(ApiError::from)
}

fn validate_ed25519_multikey(value: &str) -> Result<(), ApiError> {
    let (_, bytes) =
        multibase::decode(value).map_err(|_| ApiError::invalid("holder key is not multibase"))?;
    if bytes.len() != 34 || bytes[..2] != [0xed, 0x01] {
        return Err(ApiError::invalid(
            "holder public key is not an Ed25519 multikey",
        ));
    }
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthorized("Bearer access token is required"))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    left.len() == right.len() && left.as_bytes().ct_eq(right.as_bytes()).unwrap_u8() == 1
}

fn format_time(value: OffsetDateTime) -> Result<String, ApiError> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| ApiError::internal(error.to_string()))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use commons_identity_core::{
        Presentation, PresentationPurpose, SigningKeyMaterial, VerifiableCredential,
    };
    use serde_json::{Value, json};
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use super::*;
    use crate::model::MEMBERSHIP_CONFIGURATION;
    use crate::{
        AuthorizationRequestObject, CiKeyProof, CredentialRequest, CredentialResponse,
        DeviceRevocationRequest, EnrollmentRequest, EnrollmentResponse, PresentationRequestInput,
        PresentationRequestResponse, TokenResponse, app, verify_request_object_with_kid,
    };

    async fn issue_membership(
        state: &Arc<AppState>,
        member_reference: &str,
        persona_device_id: Uuid,
        holder: &SigningKeyMaterial,
    ) -> VerifiableCredential {
        let enrollment = EnrollmentRequest {
            enrollment_code: state.config.enrollment_code.to_string(),
            credential_configuration_id: MEMBERSHIP_CONFIGURATION.into(),
            member_reference: member_reference.into(),
            persona_device_id,
            holder_public_key_multibase: holder.public_key_multibase(),
            role: None,
        };
        let response = app(Arc::clone(state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oid4vci/enroll")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&enrollment).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let enrollment: EnrollmentResponse =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let pre_authorized_code =
            enrollment.credential_offer["grants"][PRE_AUTHORIZED_GRANT]["pre-authorized_code"]
                .as_str()
                .unwrap();
        let tx_code = enrollment
            .development_out_of_band_tx_code
            .as_deref()
            .unwrap();
        let mut wrong_form = url::form_urlencoded::Serializer::new(String::new());
        wrong_form
            .append_pair("grant_type", PRE_AUTHORIZED_GRANT)
            .append_pair("pre-authorized_code", pre_authorized_code)
            .append_pair("tx_code", "00000000");
        let wrong_response = app(Arc::clone(state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oid4vci/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(wrong_form.finish()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_response.status(), StatusCode::BAD_REQUEST);
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", PRE_AUTHORIZED_GRANT)
            .append_pair("pre-authorized_code", pre_authorized_code)
            .append_pair("tx_code", tx_code);
        let response = app(Arc::clone(state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oid4vci/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.finish()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let token: TokenResponse =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let proof = CiKeyProof::create(
            persona_device_id,
            token.c_nonce,
            state.config.public_base_url.trim_end_matches('/'),
            OffsetDateTime::now_utc(),
            holder,
        )
        .unwrap();
        let request = CredentialRequest {
            credential_configuration_id: MEMBERSHIP_CONFIGURATION.into(),
            proof,
        };
        let response = app(Arc::clone(state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oid4vci/credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", token.access_token),
                    )
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response: CredentialResponse =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(response.format, "application/vc");
        let credential = response.credentials.into_iter().next().unwrap().credential;
        credential
            .verify_with_issuer_key(&state.issuer_public_key(), OffsetDateTime::now_utc())
            .unwrap();
        credential
    }

    async fn create_presentation_request(
        state: &Arc<AppState>,
    ) -> (PresentationRequestResponse, AuthorizationRequestObject) {
        let response = app(Arc::clone(state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oid4vp/requests")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&PresentationRequestInput {
                            purpose: PresentationPurpose {
                                code: "community_document_access".into(),
                                display: "Access the community archive".into(),
                            },
                            requested_claims: vec![
                                "community".into(),
                                "membership".into(),
                                "scope".into(),
                            ],
                            retention_seconds: 300,
                            onward_sharing: false,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response: PresentationRequestResponse =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let kid = format!(
            "{}#{}",
            state.config.verifier_id,
            state.verifier_public_key()
        );
        let object = verify_request_object_with_kid(
            &response.request,
            &state.verifier_public_key(),
            Some(&kid),
        )
        .unwrap();
        (response, object)
    }

    async fn direct_post(
        state: &Arc<AppState>,
        state_value: &str,
        presentation: &Presentation,
    ) -> StatusCode {
        let vp_token = serde_json::to_string(&json!({"membership": [presentation]})).unwrap();
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("state", state_value)
            .append_pair("vp_token", &vp_token);
        app(Arc::clone(state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oid4vp/direct_post")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.finish()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn issuance_presentation_replay_and_device_revocation_are_bound() {
        let state = crate::tests::test_state();
        let authorizer_key = SigningKeyMaterial::generate();
        let target_key = SigningKeyMaterial::generate();
        let authorizer_id = Uuid::now_v7();
        let target_id = Uuid::now_v7();
        let _authorizer = issue_membership(
            &state,
            "opaque-member-reference-1",
            authorizer_id,
            &authorizer_key,
        )
        .await;
        let target =
            issue_membership(&state, "opaque-member-reference-1", target_id, &target_key).await;
        assert_eq!(target.credential_status.len(), 2);
        let wire = serde_json::to_value(&target).unwrap();
        assert_eq!(wire["credentialSubject"].get("id"), None);
        let wire_text = wire.to_string();
        assert!(!wire_text.contains(&target_id.to_string()));
        assert!(!wire_text.contains("opaque-member-reference-1"));

        let (created, object) = create_presentation_request(&state).await;
        let presentation = Presentation::create_ci_core(
            &object.ci_request,
            target.clone(),
            &target_key,
            &state.issuer_public_key(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert_eq!(
            direct_post(&state, &created.request_id, &presentation).await,
            StatusCode::OK
        );
        assert_eq!(
            direct_post(&state, &created.request_id, &presentation).await,
            StatusCode::CONFLICT
        );

        let suspension_index = target
            .credential_status
            .iter()
            .find(|reference| reference.status_purpose == "suspension")
            .unwrap()
            .status_list_index
            .parse::<usize>()
            .unwrap();
        state
            .suspension_status
            .write()
            .unwrap()
            .set(suspension_index, true, OffsetDateTime::now_utc())
            .unwrap();
        let (created, object) = create_presentation_request(&state).await;
        let suspended_presentation = Presentation::create_ci_core(
            &object.ci_request,
            target.clone(),
            &target_key,
            &state.issuer_public_key(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert_eq!(
            direct_post(&state, &created.request_id, &suspended_presentation).await,
            StatusCode::UNAUTHORIZED
        );
        state
            .suspension_status
            .write()
            .unwrap()
            .set(suspension_index, false, OffsetDateTime::now_utc())
            .unwrap();
        let (created, object) = create_presentation_request(&state).await;
        let resumed_presentation = Presentation::create_ci_core(
            &object.ci_request,
            target.clone(),
            &target_key,
            &state.issuer_public_key(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert_eq!(
            direct_post(&state, &created.request_id, &resumed_presentation).await,
            StatusCode::OK
        );

        let revocation = DeviceRevocationRequest::create(
            target_id,
            authorizer_id,
            "fresh-revocation-nonce-with-128-bits-1",
            OffsetDateTime::now_utc(),
            &authorizer_key,
        )
        .unwrap();
        let response = app(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ci/v1/device/revoke")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&revocation).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(
            response["revokedStatusIndexes"].as_array().unwrap().len(),
            1
        );

        let (created, object) = create_presentation_request(&state).await;
        let revoked_presentation = Presentation::create_ci_core(
            &object.ci_request,
            target,
            &target_key,
            &state.issuer_public_key(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert_eq!(
            direct_post(&state, &created.request_id, &revoked_presentation).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn registry_rejects_device_identity_and_holder_key_collisions() {
        let device_id = Uuid::now_v7();
        let other_device_id = Uuid::now_v7();
        let holder = SigningKeyMaterial::generate();
        let holder_key = holder.public_key_multibase();
        let existing = IssuedDevice {
            member_reference: "member-a".into(),
            persona_device_id: device_id,
            public_key_multibase: holder_key.clone(),
            revocation_index: 1,
            suspension_index: 2,
            active: true,
        };
        let registry = HashMap::from([(device_id, vec![existing])]);
        let offer = |member_reference: &str, persona_device_id, key: String| PendingOffer {
            credential_configuration_id: MEMBERSHIP_CONFIGURATION.into(),
            member_reference: member_reference.into(),
            persona_device_id,
            holder_public_key_multibase: key,
            role: None,
            tx_code_hash: "unused-in-registry-validation".into(),
            failed_tx_code_attempts: 0,
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
        };

        assert!(
            validate_registry_insertion(
                &registry,
                &offer("member-a", device_id, holder_key.clone())
            )
            .is_ok()
        );
        assert!(
            validate_registry_insertion(
                &registry,
                &offer("member-b", device_id, holder_key.clone())
            )
            .is_err()
        );
        assert!(
            validate_registry_insertion(&registry, &offer("member-a", other_device_id, holder_key))
                .is_err()
        );
    }
}
