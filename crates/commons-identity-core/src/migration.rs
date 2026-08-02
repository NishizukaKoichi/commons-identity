use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{
    PROTOCOL_ID,
    audit::AuditEntry,
    crypto::{SigningKeyMaterial, canonicalize, sha256_multibase},
    error::{CommonsError, Result},
    status::StatusList,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationPayload {
    pub authority_did_history: Vec<Value>,
    pub governance_configuration: Value,
    pub issuer_delegations: Vec<Value>,
    pub credential_schemas: BTreeMap<String, Value>,
    pub policy_versions: BTreeMap<String, Value>,
    /// Opaque ciphertext. A Migration Bundle must never contain a plaintext
    /// member registry.
    pub encrypted_member_registry: String,
    pub status_lists: Vec<StatusList>,
    pub audit_checkpoints: Vec<AuditEntry>,
    pub revocation_history: Vec<Value>,
    pub mirror_configuration: Vec<String>,
    pub pending_proposals: Vec<Value>,
    pub operator_handover_receipts: Vec<Value>,
}

impl MigrationPayload {
    pub fn validate(&self) -> Result<()> {
        if self.authority_did_history.is_empty() {
            return Err(CommonsError::InvalidInput(
                "migration requires Community Authority DID history".into(),
            ));
        }
        if self.encrypted_member_registry.len() < 32
            || !self.encrypted_member_registry.starts_with("enc:v1:")
        {
            return Err(CommonsError::InvalidInput(
                "member registry must be an enc:v1 opaque ciphertext".into(),
            ));
        }
        for value in self
            .authority_did_history
            .iter()
            .chain(self.issuer_delegations.iter())
            .chain(self.revocation_history.iter())
            .chain(self.pending_proposals.iter())
            .chain(self.operator_handover_receipts.iter())
            .chain(self.credential_schemas.values())
            .chain(self.policy_versions.values())
            .chain(std::iter::once(&self.governance_configuration))
        {
            reject_secret_shaped_fields(value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedBundle {
    bundle_version: String,
    protocol: String,
    community: String,
    source_operator: String,
    target_operator: String,
    exported_at: String,
    payload_hash: String,
    payload: MigrationPayload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommunityMigrationBundle {
    pub bundle_version: String,
    pub protocol: String,
    pub community: String,
    pub source_operator: String,
    pub target_operator: String,
    pub exported_at: String,
    pub payload_hash: String,
    pub payload: MigrationPayload,
    pub verification_method: String,
    pub signature: String,
}

impl CommunityMigrationBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        community: impl Into<String>,
        source_operator: impl Into<String>,
        target_operator: impl Into<String>,
        payload: MigrationPayload,
        now: OffsetDateTime,
        authority_key: &SigningKeyMaterial,
    ) -> Result<Self> {
        payload.validate()?;
        let community = community.into();
        let source_operator = source_operator.into();
        let target_operator = target_operator.into();
        if !community.starts_with("did:")
            || !source_operator.starts_with("did:")
            || !target_operator.starts_with("did:")
            || source_operator == target_operator
        {
            return Err(CommonsError::InvalidInput(
                "migration parties must be distinct DIDs".into(),
            ));
        }
        let payload_hash = sha256_multibase(&canonicalize(&payload)?);
        let unsigned = UnsignedBundle {
            bundle_version: "1".into(),
            protocol: PROTOCOL_ID.into(),
            community: community.clone(),
            source_operator: source_operator.clone(),
            target_operator: target_operator.clone(),
            exported_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| CommonsError::Serialization(error.to_string()))?,
            payload_hash,
            payload,
        };
        let signature = authority_key.sign_multibase(&canonicalize(&unsigned)?);
        Ok(Self {
            bundle_version: unsigned.bundle_version,
            protocol: unsigned.protocol,
            community: unsigned.community.clone(),
            source_operator: unsigned.source_operator,
            target_operator: unsigned.target_operator,
            exported_at: unsigned.exported_at,
            payload_hash: unsigned.payload_hash,
            payload: unsigned.payload,
            verification_method: format!(
                "{}#{}",
                unsigned.community,
                authority_key.public_key_multibase()
            ),
            signature,
        })
    }

    fn unsigned(&self) -> UnsignedBundle {
        UnsignedBundle {
            bundle_version: self.bundle_version.clone(),
            protocol: self.protocol.clone(),
            community: self.community.clone(),
            source_operator: self.source_operator.clone(),
            target_operator: self.target_operator.clone(),
            exported_at: self.exported_at.clone(),
            payload_hash: self.payload_hash.clone(),
            payload: self.payload.clone(),
        }
    }

    pub fn verify_for_import(
        &self,
        expected_community: &str,
        importing_operator: &str,
        authority_public_key: &str,
    ) -> Result<()> {
        if self.bundle_version != "1" || self.protocol != PROTOCOL_ID {
            return Err(CommonsError::UnsupportedFormat(
                "unsupported Community Migration Bundle".into(),
            ));
        }
        if self.community != expected_community || self.target_operator != importing_operator {
            return Err(CommonsError::Unauthorized(
                "migration bundle target does not match this operator".into(),
            ));
        }
        self.payload.validate()?;
        if self.payload_hash != sha256_multibase(&canonicalize(&self.payload)?) {
            return Err(CommonsError::Credential(
                "migration payload hash does not match".into(),
            ));
        }
        let embedded =
            SigningKeyMaterial::public_key_from_verification_method(&self.verification_method)?;
        if embedded != authority_public_key {
            return Err(CommonsError::Unauthorized(
                "migration bundle uses an unexpected authority key".into(),
            ));
        }
        let expected_verification_method = format!("{expected_community}#{authority_public_key}");
        if self.verification_method != expected_verification_method {
            return Err(CommonsError::Unauthorized(
                "migration bundle verification method is not controlled by the Community Authority"
                    .into(),
            ));
        }
        SigningKeyMaterial::verify_multibase(
            authority_public_key,
            &canonicalize(&self.unsigned())?,
            &self.signature,
        )
    }
}

fn reject_secret_shaped_fields(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let normalized = key.to_ascii_lowercase().replace(['-', '_'], "");
                if [
                    "rootsecret",
                    "holdersecret",
                    "secretkey",
                    "privatekey",
                    "recoverykit",
                    "vaultcontrolkey",
                ]
                .iter()
                .any(|forbidden| normalized.contains(forbidden))
                {
                    return Err(CommonsError::InvalidInput(format!(
                        "migration payload contains forbidden secret field: {key}"
                    )));
                }
                reject_secret_shaped_fields(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_secret_shaped_fields(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn payload() -> MigrationPayload {
        MigrationPayload {
            authority_did_history: vec![json!({"versionId": "1-zGenesis"})],
            governance_configuration: json!({"controllerCount": 5, "threshold": 3}),
            issuer_delegations: vec![],
            credential_schemas: BTreeMap::new(),
            policy_versions: BTreeMap::new(),
            encrypted_member_registry: format!("enc:v1:{}", "A".repeat(80)),
            status_lists: vec![],
            audit_checkpoints: vec![],
            revocation_history: vec![],
            mirror_configuration: vec!["https://mirror.example".into()],
            pending_proposals: vec![],
            operator_handover_receipts: vec![],
        }
    }

    #[test]
    fn signed_migration_survives_operator_change() {
        let key = SigningKeyMaterial::generate();
        let bundle = CommunityMigrationBundle::create(
            "did:webvh:community:example.org",
            "did:webvh:old:operator.example",
            "did:webvh:new:operator.example",
            payload(),
            OffsetDateTime::UNIX_EPOCH,
            &key,
        )
        .unwrap();
        bundle
            .verify_for_import(
                "did:webvh:community:example.org",
                "did:webvh:new:operator.example",
                &key.public_key_multibase(),
            )
            .unwrap();
    }

    #[test]
    fn migration_rejects_rewritten_authority_in_verification_method() {
        let key = SigningKeyMaterial::generate();
        let mut bundle = CommunityMigrationBundle::create(
            "did:webvh:community:example.org",
            "did:webvh:old:operator.example",
            "did:webvh:new:operator.example",
            payload(),
            OffsetDateTime::UNIX_EPOCH,
            &key,
        )
        .unwrap();
        bundle.verification_method = format!(
            "did:webvh:attacker:example.org#{}",
            key.public_key_multibase()
        );
        assert!(
            bundle
                .verify_for_import(
                    "did:webvh:community:example.org",
                    "did:webvh:new:operator.example",
                    &key.public_key_multibase(),
                )
                .is_err()
        );
    }

    #[test]
    fn migration_rejects_holder_secrets() {
        let mut payload = payload();
        payload
            .pending_proposals
            .push(json!({"holder_secret": "do not export"}));
        assert!(payload.validate().is_err());
    }
}
