use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    CI_CORE_CRYPTOSUITE, COMMONS_CONTEXT_V1,
    crypto::{SigningKeyMaterial, canonicalize, sha256},
    error::{CommonsError, Result},
};

pub const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CredentialKind {
    CommunityMembershipCredential,
    CommunityRoleCredential,
    CommunityCapabilityCredential,
    CommunityQualificationCredential,
    CommunityRelationshipCredential,
    ContextualStandingCredential,
    ContinuityCredential,
    OperatorCredential,
    RecognitionCredential,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommunityMembershipCredential => "CommunityMembershipCredential",
            Self::CommunityRoleCredential => "CommunityRoleCredential",
            Self::CommunityCapabilityCredential => "CommunityCapabilityCredential",
            Self::CommunityQualificationCredential => "CommunityQualificationCredential",
            Self::CommunityRelationshipCredential => "CommunityRelationshipCredential",
            Self::ContextualStandingCredential => "ContextualStandingCredential",
            Self::ContinuityCredential => "ContinuityCredential",
            Self::OperatorCredential => "OperatorCredential",
            Self::RecognitionCredential => "RecognitionCredential",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatusReference {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String,
    pub status_purpose: String,
    pub status_list_index: String,
    pub status_list_credential: String,
}

impl CredentialStatusReference {
    pub fn bitstring(
        status_list_credential: impl Into<String>,
        status_list_index: usize,
        purpose: impl Into<String>,
    ) -> Self {
        let status_list_credential = status_list_credential.into();
        let purpose = purpose.into();
        Self {
            id: format!("{status_list_credential}#{status_list_index}"),
            status_type: "BitstringStatusListEntry".into(),
            status_purpose: purpose,
            status_list_index: status_list_index.to_string(),
            status_list_credential,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderBinding {
    #[serde(rename = "type")]
    pub binding_type: String,
    pub public_key_multibase: String,
}

impl HolderBinding {
    pub fn multikey(public_key_multibase: impl Into<String>) -> Self {
        Self {
            binding_type: "Multikey".into(),
            public_key_multibase: public_key_multibase.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedCredential {
    #[serde(rename = "@context")]
    pub context: Vec<Value>,
    pub id: String,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
    pub credential_subject: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_binding: Option<HolderBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_status: Vec<CredentialStatusReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<Value>,
}

impl UnsignedCredential {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: CredentialKind,
        issuer: impl Into<String>,
        valid_from: impl Into<String>,
        valid_until: impl Into<String>,
        credential_subject: BTreeMap<String, Value>,
        holder_binding: HolderBinding,
        credential_status: Option<CredentialStatusReference>,
    ) -> Self {
        Self {
            context: vec![json!(VC_CONTEXT_V2), json!(COMMONS_CONTEXT_V1)],
            id: format!("urn:uuid:{}", Uuid::now_v7()),
            types: vec!["VerifiableCredential".into(), kind.as_str().into()],
            issuer: issuer.into(),
            valid_from: valid_from.into(),
            valid_until: valid_until.into(),
            credential_subject,
            holder_binding: Some(holder_binding),
            credential_status: credential_status.into_iter().collect(),
            credential_schema: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.context != vec![json!(VC_CONTEXT_V2), json!(COMMONS_CONTEXT_V1)] {
            return Err(CommonsError::UnsupportedFormat(
                "CI-Core credentials require the pinned VCDM and Commons contexts".into(),
            ));
        }
        if self.types.first().map(String::as_str) != Some("VerifiableCredential") {
            return Err(CommonsError::InvalidInput(
                "credential type must begin with VerifiableCredential".into(),
            ));
        }
        if self.types.len() != 2 || !is_supported_credential_type(&self.types[1]) {
            return Err(CommonsError::InvalidInput(
                "credential must contain exactly one supported Commons Identity type".into(),
            ));
        }
        if !self.issuer.starts_with("did:") {
            return Err(CommonsError::InvalidInput("issuer must be a DID".into()));
        }
        let is_status_list = self
            .types
            .iter()
            .any(|kind| kind == "BitstringStatusListCredential");
        if self.credential_subject.contains_key("id") && !is_status_list {
            return Err(CommonsError::InvalidInput(
                "credentialSubject.id is omitted by default in CI-Core".into(),
            ));
        }
        if !is_status_list {
            let community = self
                .credential_subject
                .get("community")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CommonsError::InvalidInput(
                        "Commons credential subject requires a community DID".into(),
                    )
                })?;
            if community != self.issuer {
                return Err(CommonsError::InvalidInput(
                    "credential community must equal its Community Authority issuer".into(),
                ));
            }
            if self
                .credential_subject
                .get("policyHash")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(CommonsError::InvalidInput(
                    "Commons credential subject requires policyHash".into(),
                ));
            }
        }
        let valid_from = parse_timestamp(&self.valid_from)?;
        let valid_until = parse_timestamp(&self.valid_until)?;
        if valid_until <= valid_from {
            return Err(CommonsError::InvalidInput(
                "validUntil must be after validFrom".into(),
            ));
        }
        if !is_status_list {
            validate_kind_fields(
                &self.types[1],
                &self.credential_subject,
                valid_until - valid_from,
            )?;
        }
        if let Some(binding) = &self.holder_binding {
            if binding.binding_type != "Multikey" {
                return Err(CommonsError::UnsupportedFormat(
                    "CI-Core holder binding must use Multikey".into(),
                ));
            }
            SigningKeyMaterial::validate_public_key_multibase(&binding.public_key_multibase)?;
        }
        if self.holder_binding.is_none() && !is_status_list {
            return Err(CommonsError::InvalidInput(
                "Commons Identity credentials must be holder-bound".into(),
            ));
        }
        if self.credential_status.len() > 2 {
            return Err(CommonsError::InvalidInput(
                "CI-Core credentials support at most revocation and suspension status entries"
                    .into(),
            ));
        }
        let mut purposes = BTreeSet::new();
        for status in &self.credential_status {
            if status.status_type != "BitstringStatusListEntry"
                || !matches!(status.status_purpose.as_str(), "revocation" | "suspension")
                || !purposes.insert(status.status_purpose.as_str())
            {
                return Err(CommonsError::InvalidInput(
                    "credential status entries must be unique revocation/suspension BitstringStatusList entries"
                        .into(),
                ));
            }
            let index = status.status_list_index.parse::<usize>().map_err(|_| {
                CommonsError::InvalidInput("statusListIndex must be a decimal integer".into())
            })?;
            if status.id != format!("{}#{index}", status.status_list_credential)
                || !(status.status_list_credential.starts_with("https://")
                    || status
                        .status_list_credential
                        .starts_with("http://127.0.0.1")
                    || status
                        .status_list_credential
                        .starts_with("http://localhost"))
            {
                return Err(CommonsError::InvalidInput(
                    "credential status identifier or endpoint is invalid".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn issue(
        self,
        issuer_key: &SigningKeyMaterial,
        created: &str,
    ) -> Result<VerifiableCredential> {
        self.validate()?;
        parse_timestamp(created)?;
        let verification_method = format!("{}#{}", self.issuer, issuer_key.public_key_multibase());
        let proof = DataIntegrityProof::credential_proof(
            &self.context,
            created,
            verification_method,
            &self,
            issuer_key,
        )?;
        Ok(VerifiableCredential {
            context: self.context,
            id: self.id,
            types: self.types,
            issuer: self.issuer,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            credential_subject: self.credential_subject,
            holder_binding: self.holder_binding,
            credential_status: self.credential_status,
            credential_schema: self.credential_schema,
            proof,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<Value>,
    pub id: String,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
    pub credential_subject: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_binding: Option<HolderBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_status: Vec<CredentialStatusReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<Value>,
    pub proof: DataIntegrityProof,
}

impl VerifiableCredential {
    pub fn unsigned(&self) -> UnsignedCredential {
        UnsignedCredential {
            context: self.context.clone(),
            id: self.id.clone(),
            types: self.types.clone(),
            issuer: self.issuer.clone(),
            valid_from: self.valid_from.clone(),
            valid_until: self.valid_until.clone(),
            credential_subject: self.credential_subject.clone(),
            holder_binding: self.holder_binding.clone(),
            credential_status: self.credential_status.clone(),
            credential_schema: self.credential_schema.clone(),
        }
    }

    /// Verifies cryptography, validity, and that the proof key is the issuer key
    /// already authorized by a resolved Community Authority/delegation.
    pub fn verify_with_issuer_key(
        &self,
        authorized_issuer_public_key: &str,
        now: OffsetDateTime,
    ) -> Result<()> {
        self.unsigned().validate()?;
        let valid_from = parse_timestamp(&self.valid_from)?;
        let valid_until = parse_timestamp(&self.valid_until)?;
        if now < valid_from {
            return Err(CommonsError::Credential(
                "credential is not active yet".into(),
            ));
        }
        if now >= valid_until {
            return Err(CommonsError::Credential("credential has expired".into()));
        }
        if !self
            .proof
            .verification_method
            .starts_with(&format!("{}#", self.issuer))
        {
            return Err(CommonsError::Credential(
                "proof verification method is not controlled by the credential issuer".into(),
            ));
        }
        let created = parse_timestamp(&self.proof.created)?;
        if created > now + time::Duration::minutes(5) {
            return Err(CommonsError::Credential(
                "credential proof creation time is in the future".into(),
            ));
        }
        self.proof.verify_credential(
            &self.context,
            &self.unsigned(),
            authorized_issuer_public_key,
        )
    }

    pub fn kind(&self) -> Option<&str> {
        self.types
            .iter()
            .find(|kind| kind.as_str() != "VerifiableCredential")
            .map(String::as_str)
    }
}

fn is_supported_credential_type(value: &str) -> bool {
    matches!(
        value,
        "CommunityMembershipCredential"
            | "CommunityRoleCredential"
            | "CommunityCapabilityCredential"
            | "CommunityQualificationCredential"
            | "CommunityRelationshipCredential"
            | "ContextualStandingCredential"
            | "ContinuityCredential"
            | "OperatorCredential"
            | "RecognitionCredential"
            | "BitstringStatusListCredential"
    )
}

fn validate_kind_fields(
    kind: &str,
    subject: &BTreeMap<String, Value>,
    lifetime: time::Duration,
) -> Result<()> {
    let has_scope = subject
        .get("scope")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            !items.is_empty()
                && items.iter().all(|item| {
                    item.as_str()
                        .is_some_and(|value| !value.is_empty() && value.len() <= 120)
                })
        });
    match kind {
        "CommunityMembershipCredential" => {
            if subject.get("membership").and_then(Value::as_str) != Some("active")
                || !has_scope
                || lifetime > time::Duration::days(90)
            {
                return Err(CommonsError::InvalidInput(
                    "membership credentials require membership=active, bounded scope, and at most 90 days"
                        .into(),
                ));
            }
        }
        "CommunityRoleCredential" => {
            if subject
                .get("role")
                .and_then(Value::as_str)
                .is_none_or(|role| role.is_empty() || role.len() > 80)
                || !has_scope
                || lifetime > time::Duration::days(30)
            {
                return Err(CommonsError::InvalidInput(
                    "role credentials require a bounded role, scope, and at most 30 days".into(),
                ));
            }
        }
        "CommunityCapabilityCredential" => {
            if !has_scope || lifetime > time::Duration::days(7) {
                return Err(CommonsError::InvalidInput(
                    "capability credentials require scope and at most seven days".into(),
                ));
            }
        }
        "ContextualStandingCredential" if lifetime > time::Duration::days(180) => {
            return Err(CommonsError::InvalidInput(
                "contextual standing credentials may not exceed 180 days".into(),
            ));
        }
        "OperatorCredential" if lifetime > time::Duration::days(90) => {
            return Err(CommonsError::InvalidInput(
                "operator credentials may not exceed 90 days".into(),
            ));
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    pub created: String,
    pub verification_method: String,
    pub proof_purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub proof_value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofConfiguration<'a> {
    #[serde(rename = "@context")]
    context: &'a [Value],
    #[serde(rename = "type")]
    proof_type: &'a str,
    cryptosuite: &'a str,
    created: &'a str,
    verification_method: &'a str,
    proof_purpose: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<&'a str>,
}

impl DataIntegrityProof {
    fn credential_proof<T: Serialize>(
        context: &[Value],
        created: &str,
        verification_method: String,
        document: &T,
        key: &SigningKeyMaterial,
    ) -> Result<Self> {
        let mut proof = Self {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: CI_CORE_CRYPTOSUITE.into(),
            created: created.into(),
            verification_method,
            proof_purpose: "assertionMethod".into(),
            challenge: None,
            domain: None,
            proof_value: String::new(),
        };
        proof.proof_value = key.sign_multibase(&proof.verification_data(context, document)?);
        Ok(proof)
    }

    pub(crate) fn authentication_proof<T: Serialize>(
        context: &[Value],
        created: &str,
        challenge: String,
        domain: String,
        document: &T,
        key: &SigningKeyMaterial,
    ) -> Result<Self> {
        parse_timestamp(created)?;
        let mut proof = Self {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: CI_CORE_CRYPTOSUITE.into(),
            created: created.into(),
            verification_method: key.verification_method(),
            proof_purpose: "authentication".into(),
            challenge: Some(challenge),
            domain: Some(domain),
            proof_value: String::new(),
        };
        proof.proof_value = key.sign_multibase(&proof.verification_data(context, document)?);
        Ok(proof)
    }

    fn configuration<'a>(&'a self, context: &'a [Value]) -> ProofConfiguration<'a> {
        ProofConfiguration {
            context,
            proof_type: &self.proof_type,
            cryptosuite: &self.cryptosuite,
            created: &self.created,
            verification_method: &self.verification_method,
            proof_purpose: &self.proof_purpose,
            challenge: self.challenge.as_deref(),
            domain: self.domain.as_deref(),
        }
    }

    pub(crate) fn verification_data<T: Serialize>(
        &self,
        context: &[Value],
        document: &T,
    ) -> Result<Vec<u8>> {
        let configuration_hash = sha256(&canonicalize(&self.configuration(context))?);
        let document_hash = sha256(&canonicalize(document)?);
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&configuration_hash);
        data.extend_from_slice(&document_hash);
        Ok(data)
    }

    fn validate_common(&self) -> Result<()> {
        if self.proof_type != "DataIntegrityProof" {
            return Err(CommonsError::Credential("unsupported proof type".into()));
        }
        if self.cryptosuite != CI_CORE_CRYPTOSUITE {
            return Err(CommonsError::Credential(
                "unsupported Data Integrity cryptosuite".into(),
            ));
        }
        parse_timestamp(&self.created)?;
        Ok(())
    }

    fn verify_credential<T: Serialize>(
        &self,
        context: &[Value],
        document: &T,
        authorized_issuer_public_key: &str,
    ) -> Result<()> {
        self.validate_common()?;
        if self.proof_purpose != "assertionMethod" {
            return Err(CommonsError::Credential(
                "credential proof purpose must be assertionMethod".into(),
            ));
        }
        let public_key =
            SigningKeyMaterial::public_key_from_verification_method(&self.verification_method)?;
        if public_key != authorized_issuer_public_key {
            return Err(CommonsError::Credential(
                "proof key is not authorized by the resolved issuer".into(),
            ));
        }
        SigningKeyMaterial::verify_multibase(
            &public_key,
            &self.verification_data(context, document)?,
            &self.proof_value,
        )
        .map_err(|error| CommonsError::Credential(error.to_string()))
    }

    pub(crate) fn verify_authentication<T: Serialize>(
        &self,
        context: &[Value],
        document: &T,
        expected_challenge: &str,
        expected_domain: &str,
        expected_public_key: &str,
    ) -> Result<()> {
        self.validate_common()?;
        if self.proof_purpose != "authentication" {
            return Err(CommonsError::Presentation(
                "holder proof purpose must be authentication".into(),
            ));
        }
        if self.challenge.as_deref() != Some(expected_challenge) {
            return Err(CommonsError::Presentation("nonce does not match".into()));
        }
        if self.domain.as_deref() != Some(expected_domain) {
            return Err(CommonsError::Presentation("audience does not match".into()));
        }
        let embedded_key =
            SigningKeyMaterial::public_key_from_verification_method(&self.verification_method)?;
        if embedded_key != expected_public_key {
            return Err(CommonsError::Presentation(
                "holder proof key does not match credential binding".into(),
            ));
        }
        SigningKeyMaterial::verify_multibase(
            expected_public_key,
            &self.verification_data(context, document)?,
            &self.proof_value,
        )
        .map_err(|error| CommonsError::Presentation(error.to_string()))
    }
}

pub(crate) fn parse_timestamp(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| CommonsError::InvalidInput(format!("invalid RFC 3339 timestamp: {value}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (SigningKeyMaterial, SigningKeyMaterial, UnsignedCredential) {
        let issuer = SigningKeyMaterial::generate();
        let holder = SigningKeyMaterial::generate();
        let mut subject = BTreeMap::new();
        subject.insert("community".into(), json!("did:webvh:demo:example.org"));
        subject.insert("membership".into(), json!("active"));
        subject.insert("scope".into(), json!(["community:enter"]));
        subject.insert("policyHash".into(), json!("sha256-demo-policy"));
        let unsigned = UnsignedCredential::new(
            CredentialKind::CommunityMembershipCredential,
            "did:webvh:demo:example.org",
            "2026-08-02T00:00:00Z",
            "2026-10-31T00:00:00Z",
            subject,
            HolderBinding::multikey(holder.public_key_multibase()),
            None,
        );
        (issuer, holder, unsigned)
    }

    #[test]
    fn issues_and_verifies_a_holder_bound_credential() {
        let (issuer, _, unsigned) = fixture();
        let credential = unsigned.issue(&issuer, "2026-08-02T00:00:00Z").unwrap();
        credential
            .verify_with_issuer_key(
                &issuer.public_key_multibase(),
                OffsetDateTime::parse(
                    "2026-08-03T00:00:00Z",
                    &time::format_description::well_known::Rfc3339,
                )
                .unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn rejects_tampering() {
        let (issuer, _, unsigned) = fixture();
        let mut credential = unsigned.issue(&issuer, "2026-08-02T00:00:00Z").unwrap();
        credential
            .credential_subject
            .insert("membership".into(), json!("revoked"));
        assert!(
            credential
                .verify_with_issuer_key(
                    &issuer.public_key_multibase(),
                    OffsetDateTime::parse(
                        "2026-08-03T00:00:00Z",
                        &time::format_description::well_known::Rfc3339,
                    )
                    .unwrap()
                )
                .is_err()
        );
    }

    #[test]
    fn rejects_attacker_key_in_a_trusted_issuer_fragment() {
        let (trusted_issuer, _, unsigned) = fixture();
        let attacker = SigningKeyMaterial::generate();
        let credential = unsigned.issue(&attacker, "2026-08-02T00:00:00Z").unwrap();
        let now = OffsetDateTime::parse(
            "2026-08-03T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(
            credential
                .verify_with_issuer_key(&trusted_issuer.public_key_multibase(), now)
                .is_err()
        );
    }

    #[test]
    fn forbids_global_subject_identifier_by_default() {
        let (_, _, mut unsigned) = fixture();
        unsigned
            .credential_subject
            .insert("id".into(), json!("did:example:global"));
        assert!(unsigned.validate().is_err());
    }

    #[test]
    fn issuer_did_must_control_the_proof_verification_method() {
        let (issuer, _, unsigned) = fixture();
        let mut credential = unsigned.issue(&issuer, "2026-08-02T00:00:00Z").unwrap();
        credential.proof.verification_method = format!(
            "did:webvh:attacker:example.org#{}",
            issuer.public_key_multibase()
        );
        credential.proof.proof_value = issuer.sign_multibase(
            &credential
                .proof
                .verification_data(&credential.context, &credential.unsigned())
                .unwrap(),
        );
        let now = OffsetDateTime::parse(
            "2026-08-03T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        assert!(
            credential
                .verify_with_issuer_key(&issuer.public_key_multibase(), now)
                .is_err()
        );
    }

    #[test]
    fn rejects_unpinned_contexts() {
        let (_, _, mut unsigned) = fixture();
        unsigned
            .context
            .push(json!("https://attacker.example/context"));
        assert!(unsigned.validate().is_err());
    }
}
