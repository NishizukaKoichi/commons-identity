use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use commons_identity_core::{CI_CORE_PROFILE_ID, PROTOCOL_ID};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use crate::{
    ApiError,
    model::{
        GovernanceControllerProfile, GovernanceProfile, IssuerDelegationProfile, OperatorProfile,
        SignedCommunityProfile,
    },
    state::{AppState, trim_base},
};

pub(crate) async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "protocol": PROTOCOL_ID,
        "profile": CI_CORE_PROFILE_ID,
        "community": state.config.community_id,
        "audited": false,
    }))
}

pub(crate) async fn community_profile(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SignedCommunityProfile>, ApiError> {
    let base = trim_base(&state.config.public_base_url);
    let valid_until = format_time(OffsetDateTime::now_utc() + Duration::days(90))?;
    let profile = crate::model::CommunityProfile {
        protocol: PROTOCOL_ID.into(),
        community: state.config.community_id.clone(),
        name: state.config.community_name.clone(),
        credential_issuer: base.into(),
        supported_profiles: vec![CI_CORE_PROFILE_ID.into()],
        policy_registry: format!("{base}/policies/"),
        status_services: vec![
            format!("{base}/status/revocation-1"),
            format!("{base}/status/suspension-1"),
        ],
        audit_checkpoints: format!("{base}/audit/checkpoints/"),
        mirrors: state.config.mirrors.clone(),
        governance: GovernanceProfile {
            controller_count: 5,
            update_threshold: 3,
            witness_threshold: 2,
            controllers: state
                .config
                .governance_controllers
                .iter()
                .map(|(id, public_key_multibase)| GovernanceControllerProfile {
                    id: id.clone(),
                    public_key_multibase: public_key_multibase.clone(),
                })
                .collect(),
            did_method_enforcement_note: "Commons governance approvals are recorded in the audit log; did:webvh itself does not enforce the 3-of-5 controller threshold.".into(),
        },
        operator: OperatorProfile {
            id: state.config.operator_id.clone(),
            valid_until: valid_until.clone(),
            scopes: vec![
                "credential_issuance_hosting".into(),
                "status_list_publishing".into(),
                "encrypted_member_registry_storage".into(),
                "audit_log_relay".into(),
            ],
        },
        issuer_delegation: IssuerDelegationProfile {
            verification_method: format!(
                "{}#{}",
                state.config.community_id,
                state.issuer_public_key()
            ),
            public_key_multibase: state.issuer_public_key(),
            formats: vec!["application/vc".into()],
            credential_types: vec![
                "CommunityMembershipCredential".into(),
                "CommunityRoleCredential".into(),
                "BitstringStatusListCredential".into(),
            ],
            valid_until,
        },
        implementation_status: "Developer Preview".into(),
        security_audit: "not completed".into(),
    };
    Ok(Json(SignedCommunityProfile::sign(
        profile,
        &state.authority_key,
    )?))
}

pub(crate) async fn credential_issuer_metadata(State(state): State<Arc<AppState>>) -> Json<Value> {
    let base = trim_base(&state.config.public_base_url);
    Json(json!({
        "credential_issuer": base,
        "authorization_servers": [base],
        "credential_endpoint": format!("{base}/oid4vci/credential"),
        "nonce_endpoint": format!("{base}/oid4vci/nonce"),
        "credential_offer_endpoint": format!("{base}/oid4vci/enroll"),
        "credential_configurations_supported": {
            crate::model::MEMBERSHIP_CONFIGURATION: credential_configuration(
                "Community Membership",
                "CommunityMembershipCredential",
                &["community", "membership", "scope", "policyHash"],
            ),
            crate::model::ROLE_CONFIGURATION: credential_configuration(
                "Community Role",
                "CommunityRoleCredential",
                &["community", "role", "scope", "policyHash"],
            )
        },
        "ci_authority_binding": {
            "community": state.config.community_id,
            "community_profile": format!("{base}/.well-known/commons-identity"),
            "require_exact_binding": true,
        }
    }))
}

fn credential_configuration(name: &str, credential_type: &str, claims: &[&str]) -> Value {
    json!({
        "format": "application/vc",
        "scope": format!("org.commons_identity.{credential_type}"),
        "cryptographic_binding_methods_supported": ["did:key"],
        "credential_signing_alg_values_supported": ["EdDSA"],
        "cryptosuite": "eddsa-jcs-2022",
        "proof_types_supported": {
            "ci_key_proof": {
                "proof_signing_alg_values_supported": ["EdDSA"],
                "profile": "commons-identity/1"
            }
        },
        "credential_definition": {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://nishizukakoichi.github.io/commons-identity/contexts/v1.jsonld"
            ],
            "type": ["VerifiableCredential", credential_type]
        },
        "credential_metadata": {
            "display": [{"name": name, "locale": "en"}],
            "claims": claims.iter().map(|claim| json!({
                "path": ["credentialSubject", claim],
                "mandatory": true,
            })).collect::<Vec<_>>()
        }
    })
}

pub(crate) async fn authorization_server_metadata(
    State(state): State<Arc<AppState>>,
) -> Json<Value> {
    let base = trim_base(&state.config.public_base_url);
    Json(json!({
        "issuer": base,
        "token_endpoint": format!("{base}/oid4vci/token"),
        "grant_types_supported": [crate::model::PRE_AUTHORIZED_GRANT],
        "token_endpoint_auth_methods_supported": ["none"],
        "pre-authorized_grant_anonymous_access_supported": true,
    }))
}

pub(crate) async fn context_v1() -> Response {
    let mut response = include_str!("../../../docs/contexts/v1.jsonld").into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/ld+json"),
    );
    response
}

pub(crate) async fn schema(
    State(state): State<Arc<AppState>>,
    Path(schema_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let base = trim_base(&state.config.public_base_url);
    let (title, required) = match schema_id.as_str() {
        "membership-v1" => (
            "CommunityMembershipCredential",
            vec!["community", "membership", "scope", "policyHash"],
        ),
        "role-v1" => (
            "CommunityRoleCredential",
            vec!["community", "role", "scope", "policyHash"],
        ),
        _ => return Err(ApiError::not_found("unknown schema")),
    };
    Ok(Json(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("{base}/schemas/{schema_id}"),
        "title": title,
        "type": "object",
        "required": required,
        "additionalProperties": false,
        "properties": {
            "community": {"type": "string", "pattern": "^did:"},
            "membership": {"const": "active"},
            "role": {"type": "string", "minLength": 1, "maxLength": 80},
            "scope": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "policyHash": {"type": "string", "minLength": 8}
        }
    })))
}

pub(crate) async fn policy(
    State(state): State<Arc<AppState>>,
    Path(policy_hash): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if policy_hash != state.config.policy_hash {
        return Err(ApiError::not_found("unknown policy hash"));
    }
    Ok(Json(json!({
        "protocol": PROTOCOL_ID,
        "policyHash": state.config.policy_hash,
        "credentialRetention": "The issuer retains an issuance receipt and status index, never holder presentation history.",
        "presentationTokenRetentionSeconds": 300,
        "derivedClaimsRetentionSeconds": 0,
        "onwardSharing": false,
        "analyticsUse": false,
        "advertisingUse": "prohibited",
        "enforcementNote": "Retention and onward-sharing are declared policy obligations, not cryptographic deletion guarantees."
    })))
}

pub(crate) async fn status_list(
    State(state): State<Arc<AppState>>,
    Path(status_list_id): Path<String>,
) -> Result<Response, ApiError> {
    let credential = match status_list_id.as_str() {
        "revocation-1" => state
            .revocation_status
            .read()
            .map_err(|_| ApiError::internal("status lock poisoned"))?
            .as_credential(&state.issuer_key, Duration::days(2))?,
        "suspension-1" => state
            .suspension_status
            .read()
            .map_err(|_| ApiError::internal("status lock poisoned"))?
            .as_credential(&state.issuer_key, Duration::days(2))?,
        _ => return Err(ApiError::not_found("unknown status list")),
    };
    let mut response = Json(credential).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300, stale-if-error=86400"),
    );
    Ok(response)
}

pub(crate) async fn audit_checkpoint(
    State(state): State<Arc<AppState>>,
    Path(sequence): Path<u64>,
) -> Result<Json<Value>, ApiError> {
    let audit = state
        .audit_log
        .lock()
        .map_err(|_| ApiError::internal("audit lock poisoned"))?;
    let entry = audit
        .entries
        .get(sequence as usize)
        .ok_or_else(|| ApiError::not_found("unknown audit sequence"))?;
    Ok(Json(json!({
        "authority": audit.authority,
        "authorityPublicKey": audit.authority_public_key,
        "entry": entry,
    })))
}

fn format_time(value: OffsetDateTime) -> Result<String, ApiError> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| ApiError::internal(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn signed_profile_rejects_rewritten_community_verification_method() {
        let state = crate::tests::test_state();
        let Json(mut signed) = community_profile(State(Arc::clone(&state))).await.unwrap();
        signed.verify(&state.authority_public_key()).unwrap();
        signed.verification_method = format!(
            "did:webvh:attacker:example.org#{}",
            state.authority_public_key()
        );
        assert!(signed.verify(&state.authority_public_key()).is_err());
    }

    #[tokio::test]
    async fn served_context_is_the_canonical_immutable_file() {
        let response = context_v1().await;
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/ld+json"
        );
        let served = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            served.as_ref(),
            include_str!("../../../docs/contexts/v1.jsonld").as_bytes()
        );
    }

    #[tokio::test]
    async fn schema_id_resolves_to_the_serving_operator() {
        let state = crate::tests::test_state();
        let Json(schema) = schema(State(Arc::clone(&state)), Path("membership-v1".into()))
            .await
            .unwrap();
        assert_eq!(
            schema["$id"],
            format!(
                "{}/schemas/membership-v1",
                trim_base(&state.config.public_base_url)
            )
        );
    }
}
