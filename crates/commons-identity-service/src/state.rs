use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex, RwLock},
};

use commons_identity_core::{
    AuditLog, CommunityMigrationBundle, SigningKeyMaterial, StatusList, StatusPurpose,
    status::MIN_STATUS_ENTRIES,
};
use time::OffsetDateTime;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    ApiError,
    model::{AccessGrant, IssuedDevice, PendingOffer, PendingPresentationRequest, ServiceConfig},
};

#[derive(Debug, Clone)]
pub(crate) struct OfferLocator {
    pub pre_authorized_code: String,
    pub offer: serde_json::Value,
    pub expires_at: OffsetDateTime,
}

pub(crate) const MAX_EPHEMERAL_ITEMS: usize = 4_096;
pub(crate) const MAX_ISSUED_PERSONA_DEVICES: usize = 10_000;

pub struct AppState {
    pub config: ServiceConfig,
    pub(crate) authority_key: SigningKeyMaterial,
    pub(crate) issuer_key: SigningKeyMaterial,
    pub(crate) verifier_key: SigningKeyMaterial,
    pub(crate) operator_encryption_secret: StaticSecret,
    pub(crate) offers: Mutex<HashMap<String, PendingOffer>>,
    pub(crate) offer_locators: Mutex<HashMap<String, OfferLocator>>,
    pub(crate) access_grants: Mutex<HashMap<String, AccessGrant>>,
    pub(crate) public_nonces: Mutex<HashMap<String, OffsetDateTime>>,
    pub(crate) issued_devices: Mutex<HashMap<Uuid, Vec<IssuedDevice>>>,
    pub(crate) revocation_status: RwLock<StatusList>,
    pub(crate) suspension_status: RwLock<StatusList>,
    pub(crate) audit_log: Mutex<AuditLog>,
    pub(crate) presentation_requests: Mutex<HashMap<String, PendingPresentationRequest>>,
    pub(crate) consumed_revocation_nonces: Mutex<HashMap<String, OffsetDateTime>>,
    pub(crate) consumed_governance_nonces: Mutex<HashMap<String, OffsetDateTime>>,
    pub(crate) imported_bundle: Mutex<Option<CommunityMigrationBundle>>,
}

impl AppState {
    pub fn new(config: ServiceConfig, now: OffsetDateTime) -> Result<Arc<Self>, ApiError> {
        let authority_key = SigningKeyMaterial::generate();
        let issuer_key = SigningKeyMaterial::generate();
        let verifier_key = SigningKeyMaterial::generate();
        Self::new_with_keys(config, now, authority_key, issuer_key, verifier_key)
    }

    pub fn new_with_keys(
        config: ServiceConfig,
        now: OffsetDateTime,
        authority_key: SigningKeyMaterial,
        issuer_key: SigningKeyMaterial,
        verifier_key: SigningKeyMaterial,
    ) -> Result<Arc<Self>, ApiError> {
        validate_config(&config)?;
        let operator_encryption_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let base = trim_base(&config.public_base_url);
        let revocation_status = StatusList::new(
            format!("{base}/status/revocation-1"),
            config.community_id.clone(),
            StatusPurpose::Revocation,
            MIN_STATUS_ENTRIES,
            now,
        )?;
        let suspension_status = StatusList::new(
            format!("{base}/status/suspension-1"),
            config.community_id.clone(),
            StatusPurpose::Suspension,
            MIN_STATUS_ENTRIES,
            now,
        )?;
        let audit_log = AuditLog::new(config.community_id.clone(), &authority_key);
        Ok(Arc::new(Self {
            config,
            authority_key,
            issuer_key,
            verifier_key,
            operator_encryption_secret,
            offers: Mutex::new(HashMap::new()),
            offer_locators: Mutex::new(HashMap::new()),
            access_grants: Mutex::new(HashMap::new()),
            public_nonces: Mutex::new(HashMap::new()),
            issued_devices: Mutex::new(HashMap::new()),
            revocation_status: RwLock::new(revocation_status),
            suspension_status: RwLock::new(suspension_status),
            audit_log: Mutex::new(audit_log),
            presentation_requests: Mutex::new(HashMap::new()),
            consumed_revocation_nonces: Mutex::new(HashMap::new()),
            consumed_governance_nonces: Mutex::new(HashMap::new()),
            imported_bundle: Mutex::new(None),
        }))
    }

    pub fn authority_public_key(&self) -> String {
        self.authority_key.public_key_multibase()
    }

    pub fn issuer_public_key(&self) -> String {
        self.issuer_key.public_key_multibase()
    }

    pub fn verifier_public_key(&self) -> String {
        self.verifier_key.public_key_multibase()
    }

    pub fn local_admin_token(&self) -> &str {
        self.config.admin_token.as_str()
    }

    pub fn local_enrollment_code(&self) -> &str {
        self.config.enrollment_code.as_str()
    }

    pub fn operator_encryption_public_key(&self) -> String {
        let public = X25519PublicKey::from(&self.operator_encryption_secret);
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&[0xec, 0x01]);
        bytes.extend_from_slice(public.as_bytes());
        multibase::encode(multibase::Base::Base58Btc, bytes)
    }

    pub fn refresh_status_checkpoints(&self, now: OffsetDateTime) -> Result<(), ApiError> {
        self.revocation_status
            .write()
            .map_err(|_| ApiError::internal("status lock poisoned"))?
            .touch(now)?;
        self.suspension_status
            .write()
            .map_err(|_| ApiError::internal("status lock poisoned"))?
            .touch(now)?;
        Ok(())
    }
}

pub(crate) fn trim_base(value: &str) -> &str {
    value.trim_end_matches('/')
}

fn validate_config(config: &ServiceConfig) -> Result<(), ApiError> {
    if !config.ephemeral_developer_preview {
        return Err(ApiError::invalid(
            "the reference HTTP service has no durable key/state backend and therefore only runs as an ephemeral Developer Preview",
        ));
    }
    let url = url::Url::parse(&config.public_base_url)
        .map_err(|_| ApiError::invalid("public base URL is invalid"))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(ApiError::invalid(
            "public base URL must use HTTPS except on loopback",
        ));
    }
    if !loopback {
        return Err(ApiError::invalid(
            "the ephemeral Developer Preview service is restricted to loopback",
        ));
    }
    for did in [
        &config.community_id,
        &config.operator_id,
        &config.verifier_id,
    ] {
        if !did.starts_with("did:") {
            return Err(ApiError::invalid("community actors must use DIDs"));
        }
    }
    if config.enrollment_code.len() < 12 || config.admin_token.len() < 24 {
        return Err(ApiError::invalid(
            "enrollment and admin secrets do not meet minimum length",
        ));
    }
    if config.governance_controllers.len() != 5 {
        return Err(ApiError::invalid(
            "Developer Preview migration requires exactly five configured governance controllers",
        ));
    }
    let distinct_governance_keys = config
        .governance_controllers
        .values()
        .collect::<BTreeSet<_>>();
    if distinct_governance_keys.len() != 5 {
        return Err(ApiError::invalid(
            "each governance controller must use a distinct public key",
        ));
    }
    for (controller, public_key) in &config.governance_controllers {
        if !controller.starts_with("did:") {
            return Err(ApiError::invalid(
                "governance controller identifiers must be DIDs",
            ));
        }
        SigningKeyMaterial::validate_public_key_multibase(public_key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_ephemeral_operation() {
        let state = crate::tests::test_state();
        let mut config = state.config.clone();
        config.ephemeral_developer_preview = false;
        assert!(AppState::new(config, OffsetDateTime::now_utc()).is_err());
    }

    #[test]
    fn refuses_non_loopback_operation() {
        let state = crate::tests::test_state();
        let mut config = state.config.clone();
        config.public_base_url = "https://identity.example.org".into();
        assert!(AppState::new(config, OffsetDateTime::now_utc()).is_err());
    }

    #[test]
    fn refuses_governance_controllers_that_share_one_key() {
        let state = crate::tests::test_state();
        let mut config = state.config.clone();
        let shared_key = config
            .governance_controllers
            .values()
            .next()
            .unwrap()
            .clone();
        for public_key in config.governance_controllers.values_mut() {
            *public_key = shared_key.clone();
        }
        assert!(AppState::new(config, OffsetDateTime::now_utc()).is_err());
    }
}
