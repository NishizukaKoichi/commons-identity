use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    credential::{CredentialStatusReference, VerifiableCredential},
    crypto::{DeviceKeyMaterial, Secret32, SigningKeyMaterial, pseudonym},
    error::{CommonsError, Result},
    presentation::ConsentReceipt,
    status::CredentialState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub id: Uuid,
    pub label: String,
    pub state: DeviceState,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub approved_by: Option<Uuid>,
    pub internal_keys: Option<DeviceKeyMaterial>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInstance {
    pub id: Uuid,
    pub device_id: Uuid,
    pub credential: VerifiableCredential,
    pub state: CredentialState,
    pub revocation_status: CredentialStatusReference,
    pub suspension_status: Option<CredentialStatusReference>,
    pub received_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommunityPersona {
    pub community_id: String,
    pub local_subject_id: String,
    pub local_display_name: String,
    pub community_policy_hash: String,
    persona_signing_key: SigningKeyMaterial,
    persona_holder_secret: Secret32,
    persona_nym_secret: Secret32,
    device_keys: BTreeMap<Uuid, PersonaDeviceKey>,
    pub credentials: Vec<CredentialInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersonaDeviceKey {
    /// Random identifier scoped to this persona. It is never embedded in a VC.
    binding_id: Uuid,
    keys: DeviceKeyMaterial,
}

impl CommunityPersona {
    pub fn device_public_key(&self, device_id: Uuid) -> Result<String> {
        self.device_keys
            .get(&device_id)
            .map(|entry| entry.keys.signing.public_key_multibase())
            .ok_or_else(|| CommonsError::NotFound(format!("persona device key {device_id}")))
    }

    pub fn device_signing_key(&self, device_id: Uuid) -> Result<&SigningKeyMaterial> {
        self.device_keys
            .get(&device_id)
            .map(|entry| &entry.keys.signing)
            .ok_or_else(|| CommonsError::NotFound(format!("persona device key {device_id}")))
    }

    pub fn persona_device_id(&self, device_id: Uuid) -> Result<Uuid> {
        self.device_keys
            .get(&device_id)
            .map(|entry| entry.binding_id)
            .ok_or_else(|| CommonsError::NotFound(format!("persona device key {device_id}")))
    }

    pub fn pairwise_pseudonym_preview(&self, domain: &str) -> Result<String> {
        pseudonym(&self.persona_nym_secret, domain)
    }

    pub fn persona_public_key(&self) -> String {
        self.persona_signing_key.public_key_multibase()
    }

    pub fn add_credential(
        &mut self,
        device_id: Uuid,
        credential: VerifiableCredential,
        authorized_issuer_public_key: &str,
        now: OffsetDateTime,
    ) -> Result<Uuid> {
        credential.verify_with_issuer_key(authorized_issuer_public_key, now)?;
        let device_key = self.device_public_key(device_id)?;
        let binding = credential.holder_binding.as_ref().ok_or_else(|| {
            CommonsError::Credential("credential does not contain a holder binding".into())
        })?;
        if binding.public_key_multibase != device_key {
            return Err(CommonsError::Credential(
                "credential holder binding does not match this persona device instance".into(),
            ));
        }
        if credential
            .credential_subject
            .get("community")
            .and_then(|value| value.as_str())
            != Some(self.community_id.as_str())
        {
            return Err(CommonsError::Credential(
                "credential community does not match the selected persona".into(),
            ));
        }
        let revocation_status = credential
            .credential_status
            .iter()
            .find(|entry| entry.status_purpose == "revocation")
            .cloned()
            .ok_or_else(|| {
                CommonsError::Credential(
                    "wallet requires a signed revocation status reference".into(),
                )
            })?;
        let suspension_status = credential
            .credential_status
            .iter()
            .find(|entry| entry.status_purpose == "suspension")
            .cloned();
        let id = Uuid::now_v7();
        self.credentials.push(CredentialInstance {
            id,
            device_id,
            credential,
            state: CredentialState::Active,
            revocation_status,
            suspension_status,
            received_at: format_time(now)?,
        });
        Ok(id)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryConfiguration {
    pub recovery_kit_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRevocationReport {
    pub device_id: Uuid,
    pub revoked_at: String,
    pub revoked_credential_instances: Vec<Uuid>,
    pub revocation_status_entries: Vec<CredentialStatusReference>,
    pub unaffected_device_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityVault {
    pub vault_format_version: String,
    recovery_root_secret: Secret32,
    vault_control_key: Secret32,
    vault_encryption_key: Secret32,
    pub devices: BTreeMap<Uuid, DeviceRecord>,
    pub personas: BTreeMap<String, CommunityPersona>,
    pub consent_receipts: Vec<ConsentReceipt>,
    pub recovery_configuration: RecoveryConfiguration,
    pub created_at: String,
    pub updated_at: String,
}

impl IdentityVault {
    pub fn create(first_device_label: impl Into<String>, now: OffsetDateTime) -> Result<Self> {
        let device_id = Uuid::now_v7();
        let timestamp = format_time(now)?;
        let first_device = DeviceRecord {
            id: device_id,
            label: require_label(first_device_label.into())?,
            state: DeviceState::Active,
            created_at: timestamp.clone(),
            revoked_at: None,
            approved_by: None,
            internal_keys: Some(DeviceKeyMaterial::generate()),
        };
        Ok(Self {
            vault_format_version: "1".into(),
            recovery_root_secret: Secret32::random(),
            vault_control_key: Secret32::random(),
            vault_encryption_key: Secret32::random(),
            devices: BTreeMap::from([(device_id, first_device)]),
            personas: BTreeMap::new(),
            consent_receipts: Vec::new(),
            recovery_configuration: RecoveryConfiguration::default(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
        })
    }

    pub fn first_active_device_id(&self) -> Result<Uuid> {
        self.devices
            .values()
            .find(|device| device.state == DeviceState::Active)
            .map(|device| device.id)
            .ok_or_else(|| CommonsError::NotFound("active device".into()))
    }

    pub fn add_device(
        &mut self,
        label: impl Into<String>,
        approved_by: Uuid,
        now: OffsetDateTime,
    ) -> Result<Uuid> {
        self.require_active_device(approved_by)?;
        let id = Uuid::now_v7();
        let device = DeviceRecord {
            id,
            label: require_label(label.into())?,
            state: DeviceState::Active,
            created_at: format_time(now)?,
            revoked_at: None,
            approved_by: Some(approved_by),
            internal_keys: Some(DeviceKeyMaterial::generate()),
        };
        self.devices.insert(id, device);
        for persona in self.personas.values_mut() {
            persona.device_keys.insert(
                id,
                PersonaDeviceKey {
                    binding_id: Uuid::now_v7(),
                    keys: DeviceKeyMaterial::generate(),
                },
            );
        }
        self.updated_at = format_time(now)?;
        Ok(id)
    }

    pub fn create_persona(
        &mut self,
        community_id: impl Into<String>,
        local_display_name: impl Into<String>,
        community_policy_hash: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<&CommunityPersona> {
        let community_id = community_id.into();
        if !community_id.starts_with("did:") {
            return Err(CommonsError::InvalidInput(
                "community identifier must be a DID".into(),
            ));
        }
        if self.personas.contains_key(&community_id) {
            return Err(CommonsError::InvalidInput(
                "a persona for this community already exists".into(),
            ));
        }
        let mut local_subject = [0_u8; 16];
        OsRng.fill_bytes(&mut local_subject);
        let device_keys = self
            .devices
            .values()
            .filter(|device| device.state == DeviceState::Active)
            .map(|device| {
                (
                    device.id,
                    PersonaDeviceKey {
                        binding_id: Uuid::now_v7(),
                        keys: DeviceKeyMaterial::generate(),
                    },
                )
            })
            .collect();
        let persona = CommunityPersona {
            community_id: community_id.clone(),
            local_subject_id: URL_SAFE_NO_PAD.encode(local_subject),
            local_display_name: require_label(local_display_name.into())?,
            community_policy_hash: require_policy_hash(community_policy_hash.into())?,
            persona_signing_key: SigningKeyMaterial::generate(),
            persona_holder_secret: Secret32::random(),
            persona_nym_secret: Secret32::random(),
            device_keys,
            credentials: Vec::new(),
        };
        self.personas.insert(community_id.clone(), persona);
        self.updated_at = format_time(now)?;
        Ok(self
            .personas
            .get(&community_id)
            .expect("persona was just inserted"))
    }

    pub fn persona(&self, community_id: &str) -> Result<&CommunityPersona> {
        self.personas
            .get(community_id)
            .ok_or_else(|| CommonsError::NotFound(format!("community persona {community_id}")))
    }

    pub fn persona_mut(&mut self, community_id: &str) -> Result<&mut CommunityPersona> {
        self.personas
            .get_mut(community_id)
            .ok_or_else(|| CommonsError::NotFound(format!("community persona {community_id}")))
    }

    pub fn revoke_device(
        &mut self,
        device_id: Uuid,
        approved_by: Uuid,
        now: OffsetDateTime,
    ) -> Result<DeviceRevocationReport> {
        self.require_active_device(approved_by)?;
        if approved_by == device_id {
            return Err(CommonsError::Unauthorized(
                "a device cannot be its sole revocation approver".into(),
            ));
        }
        let device = self
            .devices
            .get_mut(&device_id)
            .ok_or_else(|| CommonsError::NotFound(format!("device {device_id}")))?;
        if device.state == DeviceState::Revoked {
            return Err(CommonsError::InvalidInput(
                "device is already revoked".into(),
            ));
        }
        let revoked_at = format_time(now)?;
        device.state = DeviceState::Revoked;
        device.revoked_at = Some(revoked_at.clone());
        // Destroy the local copies of both vault-internal and per-community
        // device secrets. Public keys remain inside issued credentials.
        device.internal_keys = None;
        let mut revoked_credential_instances = Vec::new();
        let mut revocation_status_entries = Vec::new();
        for persona in self.personas.values_mut() {
            persona.device_keys.remove(&device_id);
            for instance in persona
                .credentials
                .iter_mut()
                .filter(|instance| instance.device_id == device_id)
            {
                instance.state = CredentialState::Revoked;
                revoked_credential_instances.push(instance.id);
                revocation_status_entries.push(instance.revocation_status.clone());
            }
        }
        let unaffected_device_ids = self
            .devices
            .values()
            .filter(|device| device.state == DeviceState::Active)
            .map(|device| device.id)
            .collect();
        self.updated_at = revoked_at.clone();
        Ok(DeviceRevocationReport {
            device_id,
            revoked_at,
            revoked_credential_instances,
            revocation_status_entries,
            unaffected_device_ids,
        })
    }

    pub fn record_consent(&mut self, receipt: ConsentReceipt, now: OffsetDateTime) -> Result<()> {
        self.consent_receipts.push(receipt);
        self.updated_at = format_time(now)?;
        Ok(())
    }

    pub fn mark_recovery_kit_configured(&mut self, now: OffsetDateTime) -> Result<()> {
        self.recovery_configuration.recovery_kit_configured = true;
        self.updated_at = format_time(now)?;
        Ok(())
    }

    pub(crate) fn vault_encryption_key(&self) -> &[u8; 32] {
        self.vault_encryption_key.expose()
    }

    fn require_active_device(&self, device_id: Uuid) -> Result<&DeviceRecord> {
        self.devices
            .get(&device_id)
            .filter(|device| device.state == DeviceState::Active)
            .ok_or_else(|| CommonsError::Unauthorized(format!("device {device_id} is not active")))
    }
}

fn require_label(value: String) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 120 {
        return Err(CommonsError::InvalidInput(
            "display labels must contain 1 to 120 characters".into(),
        ));
    }
    Ok(trimmed.to_string())
}

fn require_policy_hash(value: String) -> Result<String> {
    if !value.starts_with("sha256-") && !value.starts_with('z') {
        return Err(CommonsError::InvalidInput(
            "community policy hash must be sha256-* or multibase".into(),
        ));
    }
    Ok(value)
}

fn format_time(value: OffsetDateTime) -> Result<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| CommonsError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use time::Duration;

    use super::*;
    use crate::credential::{
        CredentialKind, CredentialStatusReference, HolderBinding, UnsignedCredential,
    };

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-08-02T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    }

    #[test]
    fn personas_never_reuse_subjects_or_device_keys() {
        let mut vault = IdentityVault::create("Mac", now()).unwrap();
        let device_id = vault.first_active_device_id().unwrap();
        vault
            .create_persona("did:webvh:a:school.example", "学校", "sha256-school", now())
            .unwrap();
        vault
            .create_persona("did:webvh:b:work.example", "会社", "sha256-work", now())
            .unwrap();
        let school = vault.persona("did:webvh:a:school.example").unwrap();
        let work = vault.persona("did:webvh:b:work.example").unwrap();
        assert_ne!(school.local_subject_id, work.local_subject_id);
        assert_ne!(
            school.device_public_key(device_id).unwrap(),
            work.device_public_key(device_id).unwrap()
        );
    }

    #[test]
    fn revoking_one_device_preserves_other_device_credentials() {
        let mut vault = IdentityVault::create("Mac", now()).unwrap();
        let mac = vault.first_active_device_id().unwrap();
        let phone = vault.add_device("Phone", mac, now()).unwrap();
        let community = "did:webvh:a:school.example";
        vault
            .create_persona(community, "学校", "sha256-school", now())
            .unwrap();
        let issuer = SigningKeyMaterial::generate();
        for (device, status_index) in [(mac, 10), (phone, 11)] {
            let key = vault
                .persona(community)
                .unwrap()
                .device_public_key(device)
                .unwrap();
            let mut subject = BTreeMap::new();
            subject.insert("community".into(), json!(community));
            subject.insert("membership".into(), json!("active"));
            subject.insert("scope".into(), json!(["community:enter"]));
            subject.insert("policyHash".into(), json!("sha256-school"));
            let revocation = CredentialStatusReference::bitstring(
                "https://identity.example/status/revocation-1",
                status_index,
                "revocation",
            );
            let suspension = CredentialStatusReference::bitstring(
                "https://identity.example/status/suspension-1",
                status_index + 100,
                "suspension",
            );
            let mut unsigned = UnsignedCredential::new(
                CredentialKind::CommunityMembershipCredential,
                community,
                "2026-08-01T00:00:00Z",
                "2026-10-30T00:00:00Z",
                subject,
                HolderBinding::multikey(key),
                Some(revocation),
            );
            unsigned.credential_status.push(suspension);
            let credential = unsigned.issue(&issuer, "2026-08-01T00:00:00Z").unwrap();
            vault
                .persona_mut(community)
                .unwrap()
                .add_credential(device, credential, &issuer.public_key_multibase(), now())
                .unwrap();
        }
        let report = vault
            .revoke_device(phone, mac, now() + Duration::hours(1))
            .unwrap();
        assert_eq!(report.revocation_status_entries.len(), 1);
        assert_eq!(report.revocation_status_entries[0].status_list_index, "11");
        let credentials = &vault.persona(community).unwrap().credentials;
        assert_eq!(
            credentials
                .iter()
                .find(|item| item.device_id == mac)
                .unwrap()
                .state,
            CredentialState::Active
        );
        assert_eq!(
            credentials
                .iter()
                .find(|item| item.device_id == phone)
                .unwrap()
                .state,
            CredentialState::Revoked
        );
    }

    #[test]
    fn wallet_rejects_tampered_expired_or_untrusted_credentials() {
        let mut vault = IdentityVault::create("Mac", now()).unwrap();
        let device = vault.first_active_device_id().unwrap();
        let community = "did:webvh:a:school.example";
        vault
            .create_persona(community, "学校", "sha256-school", now())
            .unwrap();
        let holder_key = vault
            .persona(community)
            .unwrap()
            .device_public_key(device)
            .unwrap();
        let issuer = SigningKeyMaterial::generate();
        let credential = |valid_from: &str, valid_until: &str| {
            let mut subject = BTreeMap::new();
            subject.insert("community".into(), json!(community));
            subject.insert("membership".into(), json!("active"));
            subject.insert("scope".into(), json!(["community:enter"]));
            subject.insert("policyHash".into(), json!("sha256-school"));
            UnsignedCredential::new(
                CredentialKind::CommunityMembershipCredential,
                community,
                valid_from,
                valid_until,
                subject,
                HolderBinding::multikey(holder_key.clone()),
                Some(CredentialStatusReference::bitstring(
                    "https://identity.example/status/revocation-1",
                    42,
                    "revocation",
                )),
            )
            .issue(&issuer, valid_from)
            .unwrap()
        };

        let mut tampered = credential("2026-08-01T00:00:00Z", "2026-10-30T00:00:00Z");
        tampered
            .credential_subject
            .insert("membership".into(), json!("active-but-tampered"));
        assert!(
            vault
                .persona_mut(community)
                .unwrap()
                .add_credential(device, tampered, &issuer.public_key_multibase(), now())
                .is_err()
        );

        let expired = credential("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z");
        assert!(
            vault
                .persona_mut(community)
                .unwrap()
                .add_credential(device, expired, &issuer.public_key_multibase(), now())
                .is_err()
        );

        let valid = credential("2026-08-01T00:00:00Z", "2026-10-30T00:00:00Z");
        assert!(
            vault
                .persona_mut(community)
                .unwrap()
                .add_credential(
                    device,
                    valid,
                    &SigningKeyMaterial::generate().public_key_multibase(),
                    now(),
                )
                .is_err()
        );
    }
}
