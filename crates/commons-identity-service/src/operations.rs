use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use axum::{Json, extract::State, http::HeaderMap};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use commons_identity_core::{
    AuditLog, AuditOperation, CommunityMigrationBundle, MigrationPayload, StatusPurpose,
    crypto::{canonicalize, sha256_multibase},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    ApiError,
    model::{
        DeviceRevocationRequest, DeviceRevocationResponse, GovernanceApproval, IssuedDevice,
        OperatorExportRequest, OperatorImportRequest, OperatorImportResponse,
    },
    state::{AppState, trim_base},
};

const REGISTRY_AAD: &[u8] = b"commons-identity/1:operator-migration-registry";

pub(crate) async fn revoke_device(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeviceRevocationRequest>,
) -> Result<Json<DeviceRevocationResponse>, ApiError> {
    let now = OffsetDateTime::now_utc();
    let mut registry = state
        .issued_devices
        .lock()
        .map_err(|_| ApiError::internal("member registry lock poisoned"))?;
    let authorizer = registry
        .get(&request.authorizing_persona_device_id)
        .and_then(|instances| instances.iter().find(|device| device.active))
        .cloned()
        .ok_or_else(|| ApiError::unauthorized("authorizing device is not active"))?;
    let targets = registry
        .get(&request.target_persona_device_id)
        .ok_or_else(|| ApiError::not_found("target device has no issued credentials"))?;
    if !targets
        .iter()
        .all(|target| target.member_reference == authorizer.member_reference)
    {
        return Err(ApiError::unauthorized(
            "devices do not belong to the same community member",
        ));
    }
    request.verify(&authorizer.public_key_multibase, now)?;
    {
        let mut nonces = state
            .consumed_revocation_nonces
            .lock()
            .map_err(|_| ApiError::internal("revocation nonce lock poisoned"))?;
        nonces.retain(|_, expires_at| now < *expires_at);
        if nonces.contains_key(&request.nonce) {
            return Err(ApiError::conflict("revocation nonce has already been used"));
        }
        if nonces.len() >= crate::state::MAX_EPHEMERAL_ITEMS {
            return Err(ApiError::conflict("too many recent revocation requests"));
        }
        nonces.insert(request.nonce.clone(), now + time::Duration::minutes(5));
    }
    let indexes: Vec<_> = targets
        .iter()
        .filter(|target| target.active)
        .map(|target| target.revocation_index)
        .collect();
    if indexes.is_empty() {
        return Err(ApiError::conflict("target device is already revoked"));
    }
    {
        let mut status = state
            .revocation_status
            .write()
            .map_err(|_| ApiError::internal("status lock poisoned"))?;
        for index in &indexes {
            status.set(*index, true, now)?;
        }
    }
    for target in registry
        .get_mut(&request.target_persona_device_id)
        .expect("target checked above")
    {
        target.active = false;
    }
    drop(registry);

    let entry_hash = state
        .audit_log
        .lock()
        .map_err(|_| ApiError::internal("audit lock poisoned"))?
        .append(
            AuditOperation::CredentialRevoked,
            &json!({
                "personaDeviceHash": sha256_multibase(
                    request.target_persona_device_id.as_bytes()
                ),
                "statusIndexesHash": sha256_multibase(&canonicalize(&indexes)?),
            }),
            vec![format!(
                "persona-device:{}",
                request.authorizing_persona_device_id
            )],
            now,
            &state.authority_key,
        )?
        .entry_hash
        .clone();
    Ok(Json(DeviceRevocationResponse {
        target_persona_device_id: request.target_persona_device_id,
        revoked_status_indexes: indexes,
        audit_entry_hash: entry_hash,
    }))
}

pub(crate) async fn export_operator(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<OperatorExportRequest>,
) -> Result<Json<CommunityMigrationBundle>, ApiError> {
    require_admin(&headers, &state.config.admin_token)?;
    if request.target_operator == state.config.operator_id {
        return Err(ApiError::invalid("target operator must be different"));
    }
    let now = OffsetDateTime::now_utc();
    let action_hash = operator_export_action_hash(
        &state.config.community_id,
        &state.config.operator_id,
        &request,
    )?;
    let context = migration_context(
        &state.config.community_id,
        &state.config.operator_id,
        &request.target_operator,
    )?;
    let registry = state
        .issued_devices
        .lock()
        .map_err(|_| ApiError::internal("member registry lock poisoned"))?;
    let encrypted_registry = encrypt_registry(
        &*registry,
        &request.target_operator_encryption_key,
        &context,
    )?;
    drop(registry);
    let approvals = verify_governance_approvals(&state, &request.approvals, &action_hash, now)?;
    state
        .audit_log
        .lock()
        .map_err(|_| ApiError::internal("audit lock poisoned"))?
        .append(
            AuditOperation::MigrationStarted,
            &json!({
                "sourceOperator": state.config.operator_id,
                "targetOperator": request.target_operator,
                "actionHash": action_hash,
            }),
            approvals,
            now,
            &state.authority_key,
        )?;
    let revocation = state
        .revocation_status
        .read()
        .map_err(|_| ApiError::internal("status lock poisoned"))?
        .clone();
    let suspension = state
        .suspension_status
        .read()
        .map_err(|_| ApiError::internal("status lock poisoned"))?
        .clone();
    let audit = state
        .audit_log
        .lock()
        .map_err(|_| ApiError::internal("audit lock poisoned"))?;
    let payload = MigrationPayload {
        authority_did_history: vec![json!({
            "method": "did:webvh",
            "community": state.config.community_id,
            "note": "Developer Preview snapshot; production import must independently resolve the did:webvh log."
        })],
        governance_configuration: json!({
            "controllerCount": 5,
            "commonsApprovalThreshold": 3,
            "witnessThreshold": 2,
        }),
        issuer_delegations: vec![json!({
            "issuerPublicKey": state.issuer_public_key(),
            "scope": [
                crate::model::MEMBERSHIP_CONFIGURATION,
                crate::model::ROLE_CONFIGURATION
            ]
        })],
        credential_schemas: BTreeMap::new(),
        policy_versions: BTreeMap::from([(
            state.config.policy_hash.clone(),
            json!({
                "uri": format!(
                    "{}/policies/{}",
                    trim_base(&state.config.public_base_url),
                    state.config.policy_hash
                )
            }),
        )]),
        encrypted_member_registry: encrypted_registry,
        status_lists: vec![revocation, suspension],
        audit_checkpoints: audit.entries.clone(),
        revocation_history: vec![],
        mirror_configuration: state.config.mirrors.clone(),
        pending_proposals: vec![],
        operator_handover_receipts: vec![],
    };
    drop(audit);
    let bundle = CommunityMigrationBundle::create(
        state.config.community_id.clone(),
        state.config.operator_id.clone(),
        request.target_operator,
        payload,
        now,
        &state.authority_key,
    )?;
    Ok(Json(bundle))
}

pub(crate) async fn import_operator(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<OperatorImportRequest>,
) -> Result<Json<OperatorImportResponse>, ApiError> {
    require_admin(&headers, &state.config.admin_token)?;
    let bundle = request.bundle;
    bundle.verify_for_import(
        &state.config.community_id,
        &state.config.operator_id,
        &state.authority_public_key(),
    )?;
    if state
        .imported_bundle
        .lock()
        .map_err(|_| ApiError::internal("migration import lock poisoned"))?
        .is_some()
    {
        return Err(ApiError::conflict(
            "an operator migration bundle is already staged; replay and rollback are refused",
        ));
    }
    let context = migration_context(
        &bundle.community,
        &bundle.source_operator,
        &bundle.target_operator,
    )?;
    let registry: std::collections::HashMap<Uuid, Vec<IssuedDevice>> = decrypt_registry(
        &bundle.payload.encrypted_member_registry,
        &state.operator_encryption_secret,
        &context,
    )?;
    let imported_count = registry.values().map(Vec::len).sum();
    let revocation = bundle
        .payload
        .status_lists
        .iter()
        .find(|list| list.purpose == StatusPurpose::Revocation)
        .cloned()
        .ok_or_else(|| ApiError::invalid("migration lacks a revocation list"))?;
    let suspension = bundle
        .payload
        .status_lists
        .iter()
        .find(|list| list.purpose == StatusPurpose::Suspension)
        .cloned()
        .ok_or_else(|| ApiError::invalid("migration lacks a suspension list"))?;
    let imported_audit = AuditLog {
        authority: state.config.community_id.clone(),
        authority_public_key: state.authority_public_key(),
        entries: bundle.payload.audit_checkpoints.clone(),
    };
    imported_audit.verify()?;
    if revocation.issuer != state.config.community_id
        || suspension.issuer != state.config.community_id
    {
        return Err(ApiError::unauthorized(
            "migration status lists are not controlled by the Community Authority",
        ));
    }
    let action_hash = operator_import_action_hash(&bundle)?;
    let _approvers = verify_governance_approvals(
        &state,
        &request.approvals,
        &action_hash,
        OffsetDateTime::now_utc(),
    )?;
    let payload_hash = bundle.payload_hash.clone();
    let mut staged = state
        .imported_bundle
        .lock()
        .map_err(|_| ApiError::internal("migration import lock poisoned"))?;
    if staged.is_some() {
        return Err(ApiError::conflict(
            "another operator migration was staged concurrently",
        ));
    }
    *staged = Some(bundle);
    Ok(Json(OperatorImportResponse {
        result: "validated_and_staged".into(),
        payload_hash,
        imported_credential_instances: imported_count,
        activation: "Live state is unchanged. Activation requires a separately implemented quorum-approved did:webvh service update, monotonic checkpoint validation, and old delegation revocation."
            .into(),
    }))
}

pub fn operator_export_action_hash(
    community: &str,
    source_operator: &str,
    request: &OperatorExportRequest,
) -> Result<String, ApiError> {
    Ok(sha256_multibase(&canonicalize(&json!({
        "protocol": commons_identity_core::PROTOCOL_ID,
        "action": "operator-export",
        "community": community,
        "sourceOperator": source_operator,
        "targetOperator": request.target_operator,
        "targetOperatorEncryptionKey": request.target_operator_encryption_key,
    }))?))
}

pub fn operator_import_action_hash(bundle: &CommunityMigrationBundle) -> Result<String, ApiError> {
    Ok(sha256_multibase(&canonicalize(&json!({
        "protocol": commons_identity_core::PROTOCOL_ID,
        "action": "operator-import-stage",
        "community": bundle.community,
        "sourceOperator": bundle.source_operator,
        "targetOperator": bundle.target_operator,
        "payloadHash": bundle.payload_hash,
        "exportedAt": bundle.exported_at,
    }))?))
}

fn encrypt_registry<T: Serialize>(
    registry: &T,
    target_public_multibase: &str,
    context: &[u8],
) -> Result<String, ApiError> {
    let target_public = decode_x25519_public(target_public_multibase)?;
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&target_public);
    if shared.as_bytes().ct_eq(&[0_u8; 32]).unwrap_u8() == 1 {
        return Err(ApiError::invalid(
            "target X25519 key produced a weak shared secret",
        ));
    }
    let key = Zeroizing::new(migration_key(
        shared.as_bytes(),
        ephemeral_public.as_bytes(),
        target_public.as_bytes(),
        context,
    ));
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let plaintext = Zeroizing::new(serde_json::to_vec(registry)?);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: context,
            },
        )
        .map_err(|_| ApiError::internal("member registry encryption failed"))?;
    let mut envelope = Vec::with_capacity(56 + ciphertext.len());
    envelope.extend_from_slice(ephemeral_public.as_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(format!("enc:v1:{}", URL_SAFE_NO_PAD.encode(envelope)))
}

fn decrypt_registry<T: DeserializeOwned>(
    encoded: &str,
    target_secret: &StaticSecret,
    context: &[u8],
) -> Result<T, ApiError> {
    let encoded = encoded
        .strip_prefix("enc:v1:")
        .ok_or_else(|| ApiError::invalid("unsupported member registry envelope"))?;
    let envelope = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::invalid("member registry is not base64url"))?;
    if envelope.len() < 32 + 24 + 16 {
        return Err(ApiError::invalid("member registry envelope is truncated"));
    }
    let ephemeral_bytes: [u8; 32] = envelope[..32]
        .try_into()
        .map_err(|_| ApiError::invalid("ephemeral key length is invalid"))?;
    let nonce: [u8; 24] = envelope[32..56]
        .try_into()
        .map_err(|_| ApiError::invalid("member registry nonce is invalid"))?;
    let ephemeral_public = X25519PublicKey::from(ephemeral_bytes);
    let target_public = X25519PublicKey::from(target_secret);
    let shared = target_secret.diffie_hellman(&ephemeral_public);
    if shared.as_bytes().ct_eq(&[0_u8; 32]).unwrap_u8() == 1 {
        return Err(ApiError::invalid("migration shared secret is weak"));
    }
    let key = Zeroizing::new(migration_key(
        shared.as_bytes(),
        ephemeral_public.as_bytes(),
        target_public.as_bytes(),
        context,
    ));
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &envelope[56..],
                    aad: context,
                },
            )
            .map_err(|_| ApiError::unauthorized("member registry could not be decrypted"))?,
    );
    serde_json::from_slice(plaintext.as_ref()).map_err(ApiError::from)
}

fn decode_x25519_public(value: &str) -> Result<X25519PublicKey, ApiError> {
    let (_, bytes) = multibase::decode(value)
        .map_err(|_| ApiError::invalid("operator encryption key is not multibase"))?;
    if bytes.len() != 34 || bytes[..2] != [0xec, 0x01] {
        return Err(ApiError::invalid(
            "operator encryption key is not an X25519 multikey",
        ));
    }
    let key: [u8; 32] = bytes[2..]
        .try_into()
        .map_err(|_| ApiError::invalid("operator encryption key length is invalid"))?;
    Ok(X25519PublicKey::from(key))
}

fn migration_key(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
    target: &[u8; 32],
    context: &[u8],
) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(REGISTRY_AAD), shared);
    let mut info = Vec::with_capacity(REGISTRY_AAD.len() + 64 + context.len());
    info.extend_from_slice(REGISTRY_AAD);
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(target);
    info.extend_from_slice(context);
    let mut key = [0_u8; 32];
    hkdf.expand(&info, &mut key)
        .expect("32-byte HKDF output is always valid for SHA-256");
    key
}

fn migration_context(community: &str, source: &str, target: &str) -> Result<Vec<u8>, ApiError> {
    canonicalize(&json!({
        "protocol": commons_identity_core::PROTOCOL_ID,
        "purpose": "operator-migration-member-registry",
        "community": community,
        "sourceOperator": source,
        "targetOperator": target,
    }))
    .map_err(ApiError::from)
}

fn require_admin(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    let supplied = headers
        .get("x-ci-admin-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("operator admin token is required"))?;
    if supplied.len() != expected.len()
        || supplied.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1
    {
        return Err(ApiError::unauthorized("operator admin token is invalid"));
    }
    Ok(())
}

fn verify_governance_approvals(
    state: &AppState,
    approvals: &[GovernanceApproval],
    expected_action_hash: &str,
    now: OffsetDateTime,
) -> Result<Vec<String>, ApiError> {
    if !(3..=state.config.governance_controllers.len()).contains(&approvals.len()) {
        return Err(ApiError::unauthorized(
            "a 3-of-5 set of signed governance approvals is required",
        ));
    }
    let mut controllers = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    for approval in approvals {
        let public_key = state
            .config
            .governance_controllers
            .get(&approval.payload.controller_id)
            .ok_or_else(|| ApiError::unauthorized("approval controller is not configured"))?;
        if !controllers.insert(approval.payload.controller_id.clone())
            || !nonces.insert(approval.payload.nonce.clone())
        {
            return Err(ApiError::unauthorized(
                "governance controller and nonce must be unique",
            ));
        }
        approval.verify(expected_action_hash, public_key, now)?;
    }
    let mut consumed = state
        .consumed_governance_nonces
        .lock()
        .map_err(|_| ApiError::internal("governance nonce lock poisoned"))?;
    consumed.retain(|_, expires_at| now < *expires_at);
    if nonces.iter().any(|nonce| consumed.contains_key(nonce)) {
        return Err(ApiError::conflict(
            "a governance approval nonce has already been consumed",
        ));
    }
    if consumed.len() + nonces.len() > crate::state::MAX_EPHEMERAL_ITEMS {
        return Err(ApiError::conflict("too many recent governance approvals"));
    }
    consumed.extend(
        nonces
            .into_iter()
            .map(|nonce| (nonce, now + time::Duration::minutes(5))),
    );
    Ok(controllers.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    fn admin_headers(state: &AppState) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-ci-admin-token",
            HeaderValue::from_str(&state.config.admin_token).unwrap(),
        );
        headers
    }

    fn approvals(action_hash: &str, suffix: &str, now: OffsetDateTime) -> Vec<GovernanceApproval> {
        (1_u8..=3)
            .map(|index| {
                let key = commons_identity_core::SigningKeyMaterial::from_secret([index; 32]);
                GovernanceApproval::create(
                    key.did_key(),
                    action_hash,
                    format!("governance-nonce-{suffix}-{index}-with-128-bits"),
                    now,
                    &key,
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn operator_registry_can_only_be_opened_by_target() {
        let target = crate::tests::test_state();
        let other = crate::tests::test_state();
        let registry = std::collections::HashMap::from([(
            Uuid::nil(),
            vec![IssuedDevice {
                member_reference: "member-1".into(),
                persona_device_id: Uuid::nil(),
                public_key_multibase: "zPublic".into(),
                revocation_index: 1,
                suspension_index: 2,
                active: true,
            }],
        )]);
        let context = migration_context(
            &target.config.community_id,
            "did:webvh:old-operator:example",
            &target.config.operator_id,
        )
        .unwrap();
        let encrypted = encrypt_registry(
            &registry,
            &target.operator_encryption_public_key(),
            &context,
        )
        .unwrap();
        let restored: std::collections::HashMap<Uuid, Vec<IssuedDevice>> =
            decrypt_registry(&encrypted, &target.operator_encryption_secret, &context).unwrap();
        assert_eq!(restored.len(), 1);
        assert!(
            decrypt_registry::<std::collections::HashMap<Uuid, Vec<IssuedDevice>>>(
                &encrypted,
                &other.operator_encryption_secret,
                &context,
            )
            .is_err()
        );
    }

    #[test]
    fn forged_governance_quorum_is_rejected() {
        let state = crate::tests::test_state();
        let action_hash = sha256_multibase(b"operator-export-action");
        let attacker = commons_identity_core::SigningKeyMaterial::generate();
        let now = OffsetDateTime::now_utc();
        let forged: Vec<_> = state
            .config
            .governance_controllers
            .keys()
            .take(3)
            .enumerate()
            .map(|(index, controller)| {
                GovernanceApproval::create(
                    controller.clone(),
                    action_hash.clone(),
                    format!("forged-governance-nonce-{index}-with-128-bits"),
                    now,
                    &attacker,
                )
                .unwrap()
            })
            .collect();
        assert!(verify_governance_approvals(&state, &forged, &action_hash, now).is_err());
    }

    #[tokio::test]
    async fn signed_migration_is_staged_without_mutating_live_state_and_replay_fails() {
        let source = crate::tests::test_state();
        let mut target_config = source.config.clone();
        target_config.operator_id = "did:webvh:new-operator:operator.example".into();
        let target = AppState::new_with_keys(
            target_config,
            OffsetDateTime::now_utc(),
            source.authority_key.clone(),
            source.issuer_key.clone(),
            source.verifier_key.clone(),
        )
        .unwrap();
        let now = OffsetDateTime::now_utc();
        let mut export_request = OperatorExportRequest {
            target_operator: target.config.operator_id.clone(),
            target_operator_encryption_key: target.operator_encryption_public_key(),
            approvals: vec![],
        };
        let export_hash = operator_export_action_hash(
            &source.config.community_id,
            &source.config.operator_id,
            &export_request,
        )
        .unwrap();
        export_request.approvals = approvals(&export_hash, "export", now);
        let bundle = export_operator(
            State(Arc::clone(&source)),
            admin_headers(&source),
            Json(export_request),
        )
        .await
        .unwrap()
        .0;

        let import_hash = operator_import_action_hash(&bundle).unwrap();
        let import_request = OperatorImportRequest {
            bundle: bundle.clone(),
            approvals: approvals(&import_hash, "import", OffsetDateTime::now_utc()),
        };
        let live_registry_before = target.issued_devices.lock().unwrap().len();
        let live_audit_before = target.audit_log.lock().unwrap().entries.len();
        let response = import_operator(
            State(Arc::clone(&target)),
            admin_headers(&target),
            Json(import_request),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(response.result, "validated_and_staged");
        assert_eq!(
            target.issued_devices.lock().unwrap().len(),
            live_registry_before
        );
        assert_eq!(
            target.audit_log.lock().unwrap().entries.len(),
            live_audit_before
        );
        assert!(target.imported_bundle.lock().unwrap().is_some());

        let replay = OperatorImportRequest {
            bundle,
            approvals: approvals(&import_hash, "replay", OffsetDateTime::now_utc()),
        };
        assert!(
            import_operator(
                State(Arc::clone(&target)),
                admin_headers(&target),
                Json(replay),
            )
            .await
            .is_err()
        );
    }
}
