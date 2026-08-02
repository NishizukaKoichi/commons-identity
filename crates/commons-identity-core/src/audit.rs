use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    crypto::{SigningKeyMaterial, canonicalize, sha256_multibase},
    error::{CommonsError, Result},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    IssuerKeyAdded,
    IssuerKeyRemoved,
    OperatorDelegated,
    OperatorRevoked,
    PolicyChanged,
    SchemaChanged,
    StatusListUpdated,
    GuardianPolicyChanged,
    MigrationStarted,
    MigrationCompleted,
    EmergencySuspension,
    CredentialRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditPayload {
    sequence: u64,
    occurred_at: String,
    operation: AuditOperation,
    target_hash: String,
    approvals: Vec<String>,
    previous_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub sequence: u64,
    pub occurred_at: String,
    pub operation: AuditOperation,
    pub target_hash: String,
    pub approvals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    pub entry_hash: String,
    pub verification_method: String,
    pub signature: String,
}

impl AuditEntry {
    fn payload(&self) -> AuditPayload {
        AuditPayload {
            sequence: self.sequence,
            occurred_at: self.occurred_at.clone(),
            operation: self.operation.clone(),
            target_hash: self.target_hash.clone(),
            approvals: self.approvals.clone(),
            previous_hash: self.previous_hash.clone(),
        }
    }

    pub fn verify(&self, expected_authority: &str, expected_public_key: &str) -> Result<()> {
        let calculated = sha256_multibase(&canonicalize(&self.payload())?);
        if calculated != self.entry_hash {
            return Err(CommonsError::Credential(
                "audit entry content hash does not match".into(),
            ));
        }
        let embedded =
            SigningKeyMaterial::public_key_from_verification_method(&self.verification_method)?;
        if embedded != expected_public_key {
            return Err(CommonsError::Credential(
                "audit entry was signed by an unexpected key".into(),
            ));
        }
        let expected_verification_method = format!("{expected_authority}#{expected_public_key}");
        if self.verification_method != expected_verification_method {
            return Err(CommonsError::Credential(
                "audit entry verification method is not controlled by the expected authority"
                    .into(),
            ));
        }
        SigningKeyMaterial::verify_multibase(
            expected_public_key,
            self.entry_hash.as_bytes(),
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLog {
    pub authority: String,
    pub authority_public_key: String,
    pub entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new(authority: impl Into<String>, authority_key: &SigningKeyMaterial) -> Self {
        Self {
            authority: authority.into(),
            authority_public_key: authority_key.public_key_multibase(),
            entries: Vec::new(),
        }
    }

    pub fn append<T: Serialize>(
        &mut self,
        operation: AuditOperation,
        target: &T,
        approvals: Vec<String>,
        now: OffsetDateTime,
        authority_key: &SigningKeyMaterial,
    ) -> Result<&AuditEntry> {
        if authority_key.public_key_multibase() != self.authority_public_key {
            return Err(CommonsError::Unauthorized(
                "audit entry key is not the configured authority key".into(),
            ));
        }
        if approvals.is_empty() {
            return Err(CommonsError::InvalidInput(
                "audit operations require at least one approval reference".into(),
            ));
        }
        let occurred_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| CommonsError::Serialization(error.to_string()))?;
        let payload = AuditPayload {
            sequence: self.entries.len() as u64,
            occurred_at,
            operation,
            target_hash: sha256_multibase(&canonicalize(target)?),
            approvals,
            previous_hash: self.entries.last().map(|entry| entry.entry_hash.clone()),
        };
        let entry_hash = sha256_multibase(&canonicalize(&payload)?);
        let entry = AuditEntry {
            sequence: payload.sequence,
            occurred_at: payload.occurred_at,
            operation: payload.operation,
            target_hash: payload.target_hash,
            approvals: payload.approvals,
            previous_hash: payload.previous_hash,
            signature: authority_key.sign_multibase(entry_hash.as_bytes()),
            verification_method: format!(
                "{}#{}",
                self.authority,
                authority_key.public_key_multibase()
            ),
            entry_hash,
        };
        self.entries.push(entry);
        Ok(self.entries.last().expect("entry was just inserted"))
    }

    pub fn verify(&self) -> Result<()> {
        let mut previous: Option<&str> = None;
        for (position, entry) in self.entries.iter().enumerate() {
            if entry.sequence != position as u64 {
                return Err(CommonsError::Credential(
                    "audit sequence is not contiguous".into(),
                ));
            }
            if entry.previous_hash.as_deref() != previous {
                return Err(CommonsError::Credential(
                    "audit hash chain is broken".into(),
                ));
            }
            entry.verify(&self.authority, &self.authority_public_key)?;
            previous = Some(&entry.entry_hash);
        }
        Ok(())
    }

    pub fn latest_checkpoint(&self) -> Option<(&str, u64)> {
        self.entries
            .last()
            .map(|entry| (entry.entry_hash.as_str(), entry.sequence))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn detects_a_tampered_hash_chain() {
        let key = SigningKeyMaterial::generate();
        let mut log = AuditLog::new("did:webvh:demo:example.org", &key);
        let now = OffsetDateTime::UNIX_EPOCH;
        log.append(
            AuditOperation::PolicyChanged,
            &json!({"policyHash": "zPolicy"}),
            vec!["controller:alice".into()],
            now,
            &key,
        )
        .unwrap();
        log.append(
            AuditOperation::OperatorDelegated,
            &json!({"operator": "did:webvh:operator"}),
            vec!["controller:alice".into(), "controller:bob".into()],
            now,
            &key,
        )
        .unwrap();
        log.verify().unwrap();
        log.entries[0].target_hash = "zTampered".into();
        assert!(log.verify().is_err());
    }

    #[test]
    fn rejects_rewritten_authority_in_verification_method() {
        let key = SigningKeyMaterial::generate();
        let mut log = AuditLog::new("did:webvh:demo:example.org", &key);
        log.append(
            AuditOperation::PolicyChanged,
            &json!({"policyHash": "zPolicy"}),
            vec!["controller:alice".into()],
            OffsetDateTime::UNIX_EPOCH,
            &key,
        )
        .unwrap();
        log.entries[0].verification_method = format!(
            "did:webvh:attacker:example.org#{}",
            key.public_key_multibase()
        );
        assert!(log.verify().is_err());
    }
}
