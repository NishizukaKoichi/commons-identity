use std::collections::{BTreeSet, HashSet};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    COMMONS_CONTEXT_V1,
    credential::{DataIntegrityProof, VC_CONTEXT_V2, VerifiableCredential, parse_timestamp},
    crypto::{SigningKeyMaterial, canonicalize, random_urlsafe, sha256_multibase},
    error::{CommonsError, Result},
};

const MAX_REQUEST_LIFETIME_SECONDS: i64 = 300;
const MAX_RETENTION_SECONDS: u64 = 31_536_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Linkability {
    None,
    VerifierDomain,
    Community,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresentationPurpose {
    pub code: String,
    pub display: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CiRequest {
    pub version: String,
    pub purpose: PresentationPurpose,
    pub requested_claims: Vec<String>,
    pub retention_seconds: u64,
    pub onward_sharing: bool,
    pub linkability: Linkability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nym_domain: Option<String>,
    pub human_review: bool,
    pub nonce: String,
    pub audience: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Value>,
}

impl CiRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        purpose: PresentationPurpose,
        requested_claims: Vec<String>,
        retention_seconds: u64,
        onward_sharing: bool,
        linkability: Linkability,
        nym_domain: Option<String>,
        audience: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<Self> {
        let mut rng = OsRng;
        let request = Self {
            version: "1".into(),
            purpose,
            requested_claims,
            retention_seconds,
            onward_sharing,
            linkability,
            nym_domain,
            human_review: false,
            nonce: random_urlsafe(&mut rng, 32),
            audience: audience.into(),
            expires_at: (now + Duration::minutes(5))
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| CommonsError::Serialization(error.to_string()))?,
            transaction_data: None,
        };
        request.validate(now)?;
        Ok(request)
    }

    pub fn validate(&self, now: OffsetDateTime) -> Result<()> {
        if self.version != "1" {
            return Err(CommonsError::InvalidInput(
                "ci_request version must be 1".into(),
            ));
        }
        if self.purpose.code.trim().is_empty() || self.purpose.display.trim().is_empty() {
            return Err(CommonsError::InvalidInput(
                "purpose code and display are required".into(),
            ));
        }
        if self.requested_claims.is_empty() {
            return Err(CommonsError::InvalidInput(
                "requestedClaims cannot be empty".into(),
            ));
        }
        let unique: BTreeSet<_> = self.requested_claims.iter().collect();
        if unique.len() != self.requested_claims.len() {
            return Err(CommonsError::InvalidInput(
                "requestedClaims must not contain duplicates".into(),
            ));
        }
        if self.requested_claims.iter().any(|claim| {
            claim.trim().is_empty()
                || claim.contains('.')
                || claim.contains('/')
                || claim.len() > 80
        }) {
            return Err(CommonsError::InvalidInput(
                "requested claims must be simple bounded property names".into(),
            ));
        }
        if self.retention_seconds > MAX_RETENTION_SECONDS {
            return Err(CommonsError::InvalidInput(
                "retentionSeconds exceeds the protocol maximum".into(),
            ));
        }
        if self.audience.trim().is_empty() {
            return Err(CommonsError::InvalidInput("audience is required".into()));
        }
        if self.nonce.len() < 22 {
            return Err(CommonsError::InvalidInput(
                "nonce must contain at least 128 bits of entropy".into(),
            ));
        }
        match self.linkability {
            Linkability::VerifierDomain => {
                if self.nym_domain.as_deref().is_none_or(str::is_empty) {
                    return Err(CommonsError::InvalidInput(
                        "nymDomain is required for verifier-domain linkability".into(),
                    ));
                }
            }
            Linkability::None | Linkability::Community => {
                if self.nym_domain.is_some() {
                    return Err(CommonsError::InvalidInput(
                        "nymDomain is only allowed with verifier-domain linkability".into(),
                    ));
                }
            }
        }
        let expires_at = parse_timestamp(&self.expires_at)?;
        if expires_at <= now {
            return Err(CommonsError::InvalidInput(
                "presentation request has expired".into(),
            ));
        }
        if expires_at - now > Duration::seconds(MAX_REQUEST_LIFETIME_SECONDS) {
            return Err(CommonsError::InvalidInput(
                "presentation request lifetime exceeds five minutes".into(),
            ));
        }
        Ok(())
    }

    /// CI-Core credentials have stable issuer proofs and cannot honestly satisfy
    /// unlinkable or verifier-only linkability. Those modes require CI-Private-BBS.
    pub fn ensure_ci_core_linkability(&self) -> Result<()> {
        if self.linkability != Linkability::Community {
            return Err(CommonsError::UnsupportedFormat(
                "CI-Core only provides community linkability; use an interoperable CI-Private-BBS implementation for none or verifier-domain"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<String> {
        Ok(sha256_multibase(&canonicalize(self)?))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedPresentation {
    #[serde(rename = "@context")]
    context: Vec<Value>,
    id: String,
    #[serde(rename = "type")]
    types: Vec<String>,
    holder: String,
    verifier: String,
    ci_request_hash: String,
    disclosed_claims: Vec<String>,
    verifiable_credential: Vec<VerifiableCredential>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: Vec<Value>,
    pub id: String,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub holder: String,
    pub verifier: String,
    pub ci_request_hash: String,
    pub disclosed_claims: Vec<String>,
    pub verifiable_credential: Vec<VerifiableCredential>,
    pub proof: DataIntegrityProof,
}

impl Presentation {
    pub fn create_ci_core(
        request: &CiRequest,
        credential: VerifiableCredential,
        holder_key: &SigningKeyMaterial,
        authorized_issuer_public_key: &str,
        now: OffsetDateTime,
    ) -> Result<Self> {
        request.validate(now)?;
        request.ensure_ci_core_linkability()?;
        credential.verify_with_issuer_key(authorized_issuer_public_key, now)?;
        let holder_binding = credential.holder_binding.as_ref().ok_or_else(|| {
            CommonsError::Unauthorized("credential does not contain a holder binding".into())
        })?;
        if holder_binding.public_key_multibase != holder_key.public_key_multibase() {
            return Err(CommonsError::Unauthorized(
                "the selected device key is not bound to this credential instance".into(),
            ));
        }
        for claim in &request.requested_claims {
            if !credential.credential_subject.contains_key(claim) {
                return Err(CommonsError::Presentation(format!(
                    "credential does not contain requested claim: {claim}"
                )));
            }
        }
        // CI-Core discloses the complete, deliberately narrow credential.
        let disclosed_claims = credential.credential_subject.keys().cloned().collect();
        let context = vec![json!(VC_CONTEXT_V2), json!(COMMONS_CONTEXT_V1)];
        let unsigned = UnsignedPresentation {
            context: context.clone(),
            id: format!("urn:uuid:{}", Uuid::now_v7()),
            types: vec![
                "VerifiablePresentation".into(),
                "CommonsPresentation".into(),
            ],
            holder: holder_key.did_key(),
            verifier: request.audience.clone(),
            ci_request_hash: request.hash()?,
            disclosed_claims,
            verifiable_credential: vec![credential],
        };
        let created = now
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| CommonsError::Serialization(error.to_string()))?;
        let proof = DataIntegrityProof::authentication_proof(
            &unsigned.context,
            &created,
            request.nonce.clone(),
            request.audience.clone(),
            &unsigned,
            holder_key,
        )?;
        Ok(Self {
            context: unsigned.context,
            id: unsigned.id,
            types: unsigned.types,
            holder: unsigned.holder,
            verifier: unsigned.verifier,
            ci_request_hash: unsigned.ci_request_hash,
            disclosed_claims: unsigned.disclosed_claims,
            verifiable_credential: unsigned.verifiable_credential,
            proof,
        })
    }

    fn unsigned(&self) -> UnsignedPresentation {
        UnsignedPresentation {
            context: self.context.clone(),
            id: self.id.clone(),
            types: self.types.clone(),
            holder: self.holder.clone(),
            verifier: self.verifier.clone(),
            ci_request_hash: self.ci_request_hash.clone(),
            disclosed_claims: self.disclosed_claims.clone(),
            verifiable_credential: self.verifiable_credential.clone(),
        }
    }

    pub fn verify_ci_core(
        &self,
        request: &CiRequest,
        authorized_issuer_public_key: &str,
        now: OffsetDateTime,
    ) -> Result<()> {
        request.validate(now)?;
        request.ensure_ci_core_linkability()?;
        if self.ci_request_hash != request.hash()? {
            return Err(CommonsError::Presentation(
                "presentation is bound to a different request".into(),
            ));
        }
        if self.verifier != request.audience {
            return Err(CommonsError::Presentation(
                "presentation verifier does not match request audience".into(),
            ));
        }
        if self.context != vec![json!(VC_CONTEXT_V2), json!(COMMONS_CONTEXT_V1)]
            || self.types
                != vec![
                    "VerifiablePresentation".to_string(),
                    "CommonsPresentation".to_string(),
                ]
        {
            return Err(CommonsError::UnsupportedFormat(
                "presentation is not the pinned CI-Core application/vp profile".into(),
            ));
        }
        if self.verifiable_credential.len() != 1 {
            return Err(CommonsError::Presentation(
                "CI-Core reference profile accepts exactly one credential per presentation".into(),
            ));
        }
        let credential = &self.verifiable_credential[0];
        credential.verify_with_issuer_key(authorized_issuer_public_key, now)?;
        let binding = credential.holder_binding.as_ref().ok_or_else(|| {
            CommonsError::Presentation("credential does not contain a holder binding".into())
        })?;
        if self.holder != format!("did:key:{}", binding.public_key_multibase) {
            return Err(CommonsError::Presentation(
                "presentation holder does not match credential holder binding".into(),
            ));
        }
        let disclosed: BTreeSet<_> = self.disclosed_claims.iter().collect();
        let actual: BTreeSet<_> = credential.credential_subject.keys().collect();
        if disclosed.len() != self.disclosed_claims.len() || disclosed != actual {
            return Err(CommonsError::Presentation(
                "CI-Core must disclose the complete narrow credential without invented claims"
                    .into(),
            ));
        }
        for requested in &request.requested_claims {
            if !self.disclosed_claims.contains(requested) {
                return Err(CommonsError::Presentation(format!(
                    "requested claim was not disclosed: {requested}"
                )));
            }
        }
        self.proof.verify_authentication(
            &self.context,
            &self.unsigned(),
            &request.nonce,
            &request.audience,
            &binding.public_key_multibase,
        )
    }

    pub fn hash(&self) -> Result<String> {
        Ok(sha256_multibase(&canonicalize(self)?))
    }
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    consumed_requests: HashSet<String>,
}

impl ReplayCache {
    pub fn verify_and_consume(
        &mut self,
        presentation: &Presentation,
        request: &CiRequest,
        authorized_issuer_public_key: &str,
        now: OffsetDateTime,
    ) -> Result<()> {
        let request_hash = request.hash()?;
        if self.consumed_requests.contains(&request_hash) {
            return Err(CommonsError::Replay);
        }
        presentation.verify_ci_core(request, authorized_issuer_public_key, now)?;
        self.consumed_requests.insert(request_hash);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentReceipt {
    pub receipt_version: String,
    pub verifier: String,
    pub purpose: String,
    pub disclosed_claims: Vec<String>,
    pub linkability: Linkability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nym_domain: Option<String>,
    pub retention_until: String,
    pub onward_sharing: bool,
    pub request_hash: String,
    pub presentation_hash: String,
    pub created_at: String,
}

impl ConsentReceipt {
    pub fn from_approved_presentation(
        request: &CiRequest,
        presentation: &Presentation,
        authorized_issuer_public_key: &str,
        now: OffsetDateTime,
    ) -> Result<Self> {
        presentation.verify_ci_core(request, authorized_issuer_public_key, now)?;
        let retention_until = now + Duration::seconds(request.retention_seconds as i64);
        Ok(Self {
            receipt_version: "1".into(),
            verifier: request.audience.clone(),
            purpose: request.purpose.code.clone(),
            disclosed_claims: presentation.disclosed_claims.clone(),
            linkability: request.linkability,
            nym_domain: request.nym_domain.clone(),
            retention_until: retention_until
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| CommonsError::Serialization(error.to_string()))?,
            onward_sharing: request.onward_sharing,
            request_hash: request.hash()?,
            presentation_hash: presentation.hash()?,
            created_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| CommonsError::Serialization(error.to_string()))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::credential::{CredentialKind, HolderBinding, UnsignedCredential};

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-08-02T10:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    }

    fn fixture() -> (CiRequest, VerifiableCredential, SigningKeyMaterial, String) {
        let issuer = SigningKeyMaterial::generate();
        let holder = SigningKeyMaterial::generate();
        let mut subject = BTreeMap::new();
        subject.insert("community".into(), json!("did:webvh:demo:example.org"));
        subject.insert("membership".into(), json!("active"));
        subject.insert("scope".into(), json!(["community:enter"]));
        subject.insert("policyHash".into(), json!("sha256-demo-policy"));
        let credential = UnsignedCredential::new(
            CredentialKind::CommunityMembershipCredential,
            "did:webvh:demo:example.org",
            "2026-08-01T00:00:00Z",
            "2026-10-30T00:00:00Z",
            subject,
            HolderBinding::multikey(holder.public_key_multibase()),
            None,
        )
        .issue(&issuer, "2026-08-01T00:00:00Z")
        .unwrap();
        let request = CiRequest::new(
            PresentationPurpose {
                code: "community_document_access".into(),
                display: "研究資料庫へアクセスするため".into(),
            },
            vec!["community".into(), "membership".into(), "scope".into()],
            300,
            false,
            Linkability::Community,
            None,
            "https://archive.example",
            now(),
        )
        .unwrap();
        (request, credential, holder, issuer.public_key_multibase())
    }

    #[test]
    fn binds_presentation_to_nonce_audience_and_holder() {
        let (request, credential, holder, issuer_key) = fixture();
        let presentation =
            Presentation::create_ci_core(&request, credential, &holder, &issuer_key, now())
                .unwrap();
        presentation
            .verify_ci_core(&request, &issuer_key, now())
            .unwrap();

        let mut different = request.clone();
        different.nonce = "different-nonce-with-enough-entropy-000".into();
        assert!(
            presentation
                .verify_ci_core(&different, &issuer_key, now())
                .is_err()
        );
    }

    #[test]
    fn rejects_replay() {
        let (request, credential, holder, issuer_key) = fixture();
        let presentation =
            Presentation::create_ci_core(&request, credential, &holder, &issuer_key, now())
                .unwrap();
        let mut cache = ReplayCache::default();
        cache
            .verify_and_consume(&presentation, &request, &issuer_key, now())
            .unwrap();
        assert!(matches!(
            cache.verify_and_consume(&presentation, &request, &issuer_key, now()),
            Err(CommonsError::Replay)
        ));
    }

    #[test]
    fn ci_core_refuses_to_overstate_unlinkability() {
        let (mut request, _, _, _) = fixture();
        request.linkability = Linkability::None;
        assert!(request.ensure_ci_core_linkability().is_err());
    }

    #[test]
    fn rejects_holder_signed_invented_disclosure_claims() {
        let (request, credential, holder, issuer_key) = fixture();
        let mut presentation =
            Presentation::create_ci_core(&request, credential, &holder, &issuer_key, now())
                .unwrap();
        presentation.disclosed_claims.push("inventedClaim".into());
        presentation.proof = DataIntegrityProof::authentication_proof(
            &presentation.context,
            &presentation.proof.created,
            request.nonce.clone(),
            request.audience.clone(),
            &presentation.unsigned(),
            &holder,
        )
        .unwrap();
        assert!(
            presentation
                .verify_ci_core(&request, &issuer_key, now())
                .is_err()
        );
    }
}
