use std::collections::BTreeMap;

use commons_identity_core::{
    CiRequest, CredentialKind, Presentation, PresentationPurpose, SigningKeyMaterial,
    credential::VerifiableCredential,
    crypto::{canonicalize, sha256_multibase},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ApiError;

pub const MEMBERSHIP_CONFIGURATION: &str = "ci_membership_v1";
pub const ROLE_CONFIGURATION: &str = "ci_role_v1";
pub const PRE_AUTHORIZED_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

#[derive(Clone)]
pub struct ServiceConfig {
    pub public_base_url: String,
    pub community_id: String,
    pub community_name: String,
    pub operator_id: String,
    pub verifier_id: String,
    pub policy_hash: String,
    pub mirrors: Vec<String>,
    pub governance_controllers: BTreeMap<String, String>,
    pub enrollment_code: Zeroizing<String>,
    pub admin_token: Zeroizing<String>,
    pub expose_demo_codes: bool,
    pub ephemeral_developer_preview: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommunityProfile {
    pub protocol: String,
    pub community: String,
    pub name: String,
    pub credential_issuer: String,
    pub supported_profiles: Vec<String>,
    pub policy_registry: String,
    pub status_services: Vec<String>,
    pub audit_checkpoints: String,
    pub mirrors: Vec<String>,
    pub governance: GovernanceProfile,
    pub operator: OperatorProfile,
    pub issuer_delegation: IssuerDelegationProfile,
    pub implementation_status: String,
    pub security_audit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceProfile {
    pub controller_count: u8,
    pub update_threshold: u8,
    pub witness_threshold: u8,
    pub controllers: Vec<GovernanceControllerProfile>,
    pub did_method_enforcement_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceControllerProfile {
    pub id: String,
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorProfile {
    pub id: String,
    pub valid_until: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerDelegationProfile {
    pub verification_method: String,
    pub public_key_multibase: String,
    pub formats: Vec<String>,
    pub credential_types: Vec<String>,
    pub valid_until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCommunityProfile {
    pub profile: CommunityProfile,
    pub verification_method: String,
    pub signature: String,
}

impl SignedCommunityProfile {
    pub fn sign(profile: CommunityProfile, key: &SigningKeyMaterial) -> Result<Self, ApiError> {
        let signature = key.sign_multibase(&canonicalize(&profile)?);
        Ok(Self {
            verification_method: format!("{}#{}", profile.community, key.public_key_multibase()),
            profile,
            signature,
        })
    }

    pub fn verify(&self, expected_public_key: &str) -> Result<(), ApiError> {
        let embedded =
            SigningKeyMaterial::public_key_from_verification_method(&self.verification_method)?;
        if embedded != expected_public_key {
            return Err(ApiError::unauthorized(
                "Community Profile is signed by an unexpected key",
            ));
        }
        let expected_verification_method =
            format!("{}#{expected_public_key}", self.profile.community);
        if self.verification_method != expected_verification_method {
            return Err(ApiError::unauthorized(
                "Community Profile verification method is not controlled by the Community Authority",
            ));
        }
        SigningKeyMaterial::verify_multibase(
            expected_public_key,
            &canonicalize(&self.profile)?,
            &self.signature,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentRequest {
    pub enrollment_code: String,
    pub credential_configuration_id: String,
    pub member_reference: String,
    pub persona_device_id: Uuid,
    pub holder_public_key_multibase: String,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentResponse {
    pub credential_offer_uri: String,
    pub credential_offer: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub development_out_of_band_tx_code: Option<String>,
    pub expires_in: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingOffer {
    pub credential_configuration_id: String,
    pub member_reference: String,
    pub persona_device_id: Uuid,
    pub holder_public_key_multibase: String,
    pub role: Option<String>,
    pub tx_code_hash: String,
    pub failed_tx_code_attempts: u8,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    pub tx_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub c_nonce: String,
}

#[derive(Debug, Clone)]
pub(crate) struct AccessGrant {
    pub offer: PendingOffer,
    pub c_nonce: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CiKeyProofPayload {
    pub proof_version: String,
    pub public_key_multibase: String,
    pub persona_device_id: Uuid,
    pub c_nonce: String,
    pub audience: String,
    pub issued_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CiKeyProof {
    pub proof_type: String,
    pub payload: CiKeyProofPayload,
    pub proof_value: String,
}

impl CiKeyProof {
    pub fn create(
        persona_device_id: Uuid,
        c_nonce: impl Into<String>,
        audience: impl Into<String>,
        now: OffsetDateTime,
        key: &SigningKeyMaterial,
    ) -> Result<Self, ApiError> {
        let payload = CiKeyProofPayload {
            proof_version: "1".into(),
            public_key_multibase: key.public_key_multibase(),
            persona_device_id,
            c_nonce: c_nonce.into(),
            audience: audience.into(),
            issued_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| ApiError::invalid(error.to_string()))?,
        };
        Ok(Self {
            proof_type: "ci_key_proof".into(),
            proof_value: key.sign_multibase(&canonicalize(&payload)?),
            payload,
        })
    }

    pub fn verify(
        &self,
        expected_nonce: &str,
        expected_audience: &str,
        now: OffsetDateTime,
    ) -> Result<(), ApiError> {
        if self.proof_type != "ci_key_proof" || self.payload.proof_version != "1" {
            return Err(ApiError::invalid("unsupported CI key proof"));
        }
        if self.payload.c_nonce != expected_nonce || self.payload.audience != expected_audience {
            return Err(ApiError::unauthorized(
                "CI key proof nonce or audience does not match",
            ));
        }
        let issued_at = OffsetDateTime::parse(
            &self.payload.issued_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| ApiError::invalid("CI key proof issuedAt is invalid"))?;
        if (now - issued_at).abs() > time::Duration::minutes(5) {
            return Err(ApiError::unauthorized(
                "CI key proof is outside its time window",
            ));
        }
        SigningKeyMaterial::verify_multibase(
            &self.payload.public_key_multibase,
            &canonicalize(&self.payload)?,
            &self.proof_value,
        )?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    pub credential_configuration_id: String,
    pub proof: CiKeyProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialResult {
    pub credential: VerifiableCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialResponse {
    pub format: String,
    pub credentials: Vec<CredentialResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IssuedDevice {
    pub member_reference: String,
    pub persona_device_id: Uuid,
    pub public_key_multibase: String,
    pub revocation_index: usize,
    pub suspension_index: usize,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationRequestInput {
    pub purpose: PresentationPurpose,
    pub requested_claims: Vec<String>,
    pub retention_seconds: u64,
    pub onward_sharing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DcqlCredentialQuery {
    pub id: String,
    pub format: String,
    pub meta: Value,
    pub claims: Vec<DcqlClaimQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlClaimQuery {
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlQuery {
    pub credentials: Vec<DcqlCredentialQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequestObject {
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub client_id: String,
    pub response_type: String,
    pub response_mode: String,
    pub response_uri: String,
    pub nonce: String,
    pub state: String,
    pub dcql_query: DcqlQuery,
    pub ci_request: CiRequest,
    pub client_metadata: Value,
}

impl AuthorizationRequestObject {
    pub fn validate_ci_alignment(&self, now: OffsetDateTime) -> Result<(), ApiError> {
        self.ci_request.validate(now)?;
        let now_unix = now.unix_timestamp();
        if self.iat > now_unix + 60
            || self.exp <= now_unix
            || self.exp <= self.iat
            || self.exp - self.iat > 300
        {
            return Err(ApiError::invalid(
                "signed request object is expired or outside its five-minute time window",
            ));
        }
        if self.iss != self.ci_request.audience || self.aud != "https://self-issued.me/v2" {
            return Err(ApiError::invalid(
                "request object issuer or audience is not bound to the verifier",
            ));
        }
        if self.response_type != "vp_token" || self.response_mode != "direct_post" {
            return Err(ApiError::invalid(
                "Commons Identity profile requires vp_token and direct_post",
            ));
        }
        if self.nonce != self.ci_request.nonce {
            return Err(ApiError::invalid(
                "OID4VP nonce and ci_request nonce differ",
            ));
        }
        if self.client_id != format!("decentralized_identifier:{}", self.ci_request.audience) {
            return Err(ApiError::invalid(
                "client_id and ci_request audience are not exactly bound",
            ));
        }
        if self.state.len() < 22 {
            return Err(ApiError::invalid(
                "authorization response state must contain at least 128 bits of entropy",
            ));
        }
        let response_uri = url::Url::parse(&self.response_uri)
            .map_err(|_| ApiError::invalid("response_uri is invalid"))?;
        let loopback = matches!(
            response_uri.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]")
        );
        if response_uri.scheme() != "https" && !(response_uri.scheme() == "http" && loopback) {
            return Err(ApiError::invalid(
                "response_uri must use HTTPS except on loopback",
            ));
        }
        if self
            .client_metadata
            .get("ci_request_required")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(ApiError::invalid(
                "client metadata must require fail-closed ci_request processing",
            ));
        }
        let credential = self
            .dcql_query
            .credentials
            .first()
            .ok_or_else(|| ApiError::invalid("DCQL query contains no credential"))?;
        if self.dcql_query.credentials.len() != 1
            || credential.id != "membership"
            || credential.format != "application/vc"
        {
            return Err(ApiError::invalid(
                "CI-Core request must contain one application/vc query",
            ));
        }
        let dcql_claims: Vec<_> = credential
            .claims
            .iter()
            .map(|claim| {
                if claim.path.len() != 2 || claim.path[0] != "credentialSubject" {
                    return Err(ApiError::invalid(
                        "DCQL claim must be rooted at credentialSubject",
                    ));
                }
                Ok(claim.path[1].clone())
            })
            .collect::<Result<_, ApiError>>()?;
        if dcql_claims != self.ci_request.requested_claims {
            return Err(ApiError::invalid(
                "DCQL claims and ci_request requestedClaims differ",
            ));
        }
        if credential.meta.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022") {
            return Err(ApiError::invalid(
                "DCQL query must pin the CI-Core cryptosuite",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PendingPresentationRequest {
    pub object: AuthorizationRequestObject,
    pub request_jwt: String,
    pub consumed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationRequestResponse {
    pub request_id: String,
    pub request_uri: String,
    pub request: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct DirectPostForm {
    pub state: String,
    pub vp_token: String,
}

#[derive(Debug, Deserialize)]
pub struct VpToken {
    pub membership: Vec<Presentation>,
}

#[derive(Debug, Serialize)]
pub struct DirectPostResponse {
    pub result: String,
    pub presentation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRevocationRequest {
    pub request_version: String,
    pub target_persona_device_id: Uuid,
    pub authorizing_persona_device_id: Uuid,
    pub created_at: String,
    pub nonce: String,
    pub signature: String,
}

impl DeviceRevocationRequest {
    fn unsigned(&self) -> BTreeMap<&str, Value> {
        BTreeMap::from([
            (
                "authorizingPersonaDeviceId",
                Value::String(self.authorizing_persona_device_id.to_string()),
            ),
            ("createdAt", Value::String(self.created_at.clone())),
            ("nonce", Value::String(self.nonce.clone())),
            (
                "requestVersion",
                Value::String(self.request_version.clone()),
            ),
            (
                "targetPersonaDeviceId",
                Value::String(self.target_persona_device_id.to_string()),
            ),
        ])
    }

    pub fn create(
        target_persona_device_id: Uuid,
        authorizing_persona_device_id: Uuid,
        nonce: impl Into<String>,
        now: OffsetDateTime,
        authorizing_key: &SigningKeyMaterial,
    ) -> Result<Self, ApiError> {
        let mut request = Self {
            request_version: "1".into(),
            target_persona_device_id,
            authorizing_persona_device_id,
            created_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| ApiError::invalid(error.to_string()))?,
            nonce: nonce.into(),
            signature: String::new(),
        };
        request.signature = authorizing_key.sign_multibase(&canonicalize(&request.unsigned())?);
        Ok(request)
    }

    pub fn verify(&self, public_key: &str, now: OffsetDateTime) -> Result<(), ApiError> {
        if self.request_version != "1"
            || self.target_persona_device_id == self.authorizing_persona_device_id
            || self.nonce.len() < 22
        {
            return Err(ApiError::invalid("invalid device revocation request"));
        }
        let created = OffsetDateTime::parse(
            &self.created_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| ApiError::invalid("invalid device revocation timestamp"))?;
        if (now - created).abs() > time::Duration::minutes(5) {
            return Err(ApiError::unauthorized(
                "device revocation request is outside its time window",
            ));
        }
        SigningKeyMaterial::verify_multibase(
            public_key,
            &canonicalize(&self.unsigned())?,
            &self.signature,
        )?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRevocationResponse {
    pub target_persona_device_id: Uuid,
    pub revoked_status_indexes: Vec<usize>,
    pub audit_entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorExportRequest {
    pub target_operator: String,
    pub target_operator_encryption_key: String,
    pub approvals: Vec<GovernanceApproval>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorImportRequest {
    pub bundle: commons_identity_core::CommunityMigrationBundle,
    pub approvals: Vec<GovernanceApproval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceApprovalPayload {
    pub approval_version: String,
    pub controller_id: String,
    pub action_hash: String,
    pub issued_at: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceApproval {
    pub payload: GovernanceApprovalPayload,
    pub signature: String,
}

impl GovernanceApproval {
    pub fn create(
        controller_id: impl Into<String>,
        action_hash: impl Into<String>,
        nonce: impl Into<String>,
        now: OffsetDateTime,
        key: &SigningKeyMaterial,
    ) -> Result<Self, ApiError> {
        let payload = GovernanceApprovalPayload {
            approval_version: "1".into(),
            controller_id: controller_id.into(),
            action_hash: action_hash.into(),
            issued_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| ApiError::invalid(error.to_string()))?,
            nonce: nonce.into(),
        };
        if payload.nonce.len() < 22 {
            return Err(ApiError::invalid(
                "governance approval nonce must contain at least 128 bits of entropy",
            ));
        }
        Ok(Self {
            signature: key.sign_multibase(&canonicalize(&payload)?),
            payload,
        })
    }

    pub fn verify(
        &self,
        expected_action_hash: &str,
        expected_public_key: &str,
        now: OffsetDateTime,
    ) -> Result<(), ApiError> {
        if self.payload.approval_version != "1"
            || self.payload.action_hash != expected_action_hash
            || self.payload.nonce.len() < 22
        {
            return Err(ApiError::unauthorized(
                "governance approval is not bound to this action",
            ));
        }
        let issued_at = OffsetDateTime::parse(
            &self.payload.issued_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| ApiError::invalid("governance approval timestamp is invalid"))?;
        if (now - issued_at).abs() > time::Duration::minutes(5) {
            return Err(ApiError::unauthorized(
                "governance approval is outside its five-minute window",
            ));
        }
        SigningKeyMaterial::verify_multibase(
            expected_public_key,
            &canonicalize(&self.payload)?,
            &self.signature,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorImportResponse {
    pub result: String,
    pub payload_hash: String,
    pub imported_credential_instances: usize,
    pub activation: String,
}

pub(crate) fn offer_hash(value: &str) -> String {
    sha256_multibase(value.as_bytes())
}

pub(crate) fn credential_kind(configuration_id: &str) -> Result<CredentialKind, ApiError> {
    match configuration_id {
        MEMBERSHIP_CONFIGURATION => Ok(CredentialKind::CommunityMembershipCredential),
        ROLE_CONFIGURATION => Ok(CredentialKind::CommunityRoleCredential),
        _ => Err(ApiError::invalid("unsupported credential configuration")),
    }
}
