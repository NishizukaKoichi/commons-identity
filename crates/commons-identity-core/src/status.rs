use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
};

use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use multibase::Base;
use rand::{Rng, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use crate::{
    COMMONS_CONTEXT_V1,
    credential::{UnsignedCredential, VC_CONTEXT_V2, VerifiableCredential},
    crypto::SigningKeyMaterial,
    error::{CommonsError, Result},
};

pub const MIN_STATUS_ENTRIES: usize = 131_072;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusPurpose {
    Revocation,
    Suspension,
}

impl StatusPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revocation => "revocation",
            Self::Suspension => "suspension",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialState {
    Active,
    Suspended,
    Revoked,
    Superseded,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum StatusAssessment {
    Active {
        last_status_update: String,
    },
    Listed {
        purpose: StatusPurpose,
        last_status_update: String,
    },
    CurrentStatusUnknown {
        last_status_update: String,
        age_seconds: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusList {
    pub id: String,
    pub issuer: String,
    pub purpose: StatusPurpose,
    pub size: usize,
    pub updated_at: String,
    pub sequence: u64,
    next_index: usize,
    allocated: BTreeSet<usize>,
    bits: Vec<u8>,
}

impl StatusList {
    pub fn new(
        id: impl Into<String>,
        issuer: impl Into<String>,
        purpose: StatusPurpose,
        size: usize,
        now: OffsetDateTime,
    ) -> Result<Self> {
        if size < MIN_STATUS_ENTRIES || !size.is_multiple_of(8) {
            return Err(CommonsError::InvalidInput(format!(
                "status list must contain a multiple of eight and at least {MIN_STATUS_ENTRIES} entries"
            )));
        }
        Ok(Self {
            id: id.into(),
            issuer: issuer.into(),
            purpose,
            size,
            updated_at: format_time(now)?,
            sequence: 0,
            next_index: 0,
            allocated: BTreeSet::new(),
            bits: vec![0_u8; size / 8],
        })
    }

    #[cfg(test)]
    fn allocate(&mut self) -> Result<usize> {
        while self.next_index < self.size && self.allocated.contains(&self.next_index) {
            self.next_index += 1;
        }
        if self.next_index >= self.size {
            return Err(CommonsError::InvalidInput(
                "status list has no unallocated entries".into(),
            ));
        }
        let index = self.next_index;
        self.next_index += 1;
        self.allocated.insert(index);
        Ok(index)
    }

    /// Allocates a privacy-preserving random index as recommended by the
    /// Bitstring Status List specification.
    pub fn allocate_random(&mut self) -> Result<usize> {
        if self.allocated.len() >= self.size {
            return Err(CommonsError::InvalidInput(
                "status list has no unallocated entries".into(),
            ));
        }
        let mut rng = OsRng;
        for _ in 0..256 {
            let index = rng.gen_range(0..self.size);
            if self.allocated.insert(index) {
                return Ok(index);
            }
        }
        // Deterministic fallback only matters close to exhaustion.
        let index = (0..self.size)
            .find(|index| !self.allocated.contains(index))
            .ok_or_else(|| CommonsError::InvalidInput("status list is exhausted".into()))?;
        self.allocated.insert(index);
        Ok(index)
    }

    pub fn set(&mut self, index: usize, listed: bool, now: OffsetDateTime) -> Result<()> {
        self.ensure_allocated(index)?;
        let byte = index / 8;
        let mask = 1_u8 << (index % 8);
        if self.purpose == StatusPurpose::Revocation && !listed && self.bits[byte] & mask != 0 {
            return Err(CommonsError::InvalidInput(
                "a revocation bit is permanent and cannot be cleared".into(),
            ));
        }
        if listed {
            self.bits[byte] |= mask;
        } else {
            self.bits[byte] &= !mask;
        }
        self.updated_at = format_time(now)?;
        self.sequence = self.sequence.saturating_add(1);
        Ok(())
    }

    /// Republishes an unchanged list as a fresh, signed checkpoint.
    pub fn touch(&mut self, now: OffsetDateTime) -> Result<()> {
        let previous = crate::credential::parse_timestamp(&self.updated_at)?;
        if now < previous {
            return Err(CommonsError::InvalidInput(
                "status checkpoint time cannot move backwards".into(),
            ));
        }
        self.updated_at = format_time(now)?;
        self.sequence = self.sequence.saturating_add(1);
        Ok(())
    }

    pub fn is_listed(&self, index: usize) -> Result<bool> {
        self.ensure_allocated(index)?;
        Ok(self.bits[index / 8] & (1_u8 << (index % 8)) != 0)
    }

    pub fn assess(
        &self,
        index: usize,
        max_age: Duration,
        now: OffsetDateTime,
    ) -> Result<StatusAssessment> {
        self.ensure_allocated(index)?;
        let updated = crate::credential::parse_timestamp(&self.updated_at)?;
        let age = now - updated;
        if age.is_negative() {
            return Ok(StatusAssessment::CurrentStatusUnknown {
                last_status_update: self.updated_at.clone(),
                age_seconds: age.whole_seconds(),
            });
        }
        if age > max_age {
            return Ok(StatusAssessment::CurrentStatusUnknown {
                last_status_update: self.updated_at.clone(),
                age_seconds: age.whole_seconds(),
            });
        }
        if self.is_listed(index)? {
            Ok(StatusAssessment::Listed {
                purpose: self.purpose,
                last_status_update: self.updated_at.clone(),
            })
        } else {
            Ok(StatusAssessment::Active {
                last_status_update: self.updated_at.clone(),
            })
        }
    }

    pub fn encoded_list(&self) -> Result<String> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&self.bits)
            .map_err(|error| CommonsError::Serialization(error.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|error| CommonsError::Serialization(error.to_string()))?;
        Ok(multibase::encode(Base::Base64Url, compressed))
    }

    pub fn decode_list(encoded: &str, expected_size: usize) -> Result<Vec<u8>> {
        let (_, compressed) = multibase::decode(encoded)
            .map_err(|error| CommonsError::Serialization(error.to_string()))?;
        let decoder = GzDecoder::new(compressed.as_slice());
        let mut bits = Vec::new();
        decoder
            .take((expected_size / 8 + 1) as u64)
            .read_to_end(&mut bits)
            .map_err(|error| CommonsError::Serialization(error.to_string()))?;
        if bits.len() != expected_size / 8 {
            return Err(CommonsError::InvalidInput(
                "decoded status list has an unexpected size".into(),
            ));
        }
        Ok(bits)
    }

    pub fn as_credential(
        &self,
        issuer_key: &SigningKeyMaterial,
        valid_for: Duration,
    ) -> Result<VerifiableCredential> {
        let valid_from = crate::credential::parse_timestamp(&self.updated_at)?;
        let mut subject = BTreeMap::<String, Value>::new();
        subject.insert("id".into(), json!(format!("{}#list", self.id)));
        subject.insert("type".into(), json!("BitstringStatusList"));
        subject.insert("statusPurpose".into(), json!(self.purpose.as_str()));
        subject.insert("encodedList".into(), json!(self.encoded_list()?));
        let unsigned = UnsignedCredential {
            context: vec![json!(VC_CONTEXT_V2), json!(COMMONS_CONTEXT_V1)],
            id: self.id.clone(),
            types: vec![
                "VerifiableCredential".into(),
                "BitstringStatusListCredential".into(),
            ],
            issuer: self.issuer.clone(),
            valid_from: format_time(valid_from)?,
            valid_until: format_time(valid_from + valid_for)?,
            credential_subject: subject,
            holder_binding: None,
            credential_status: vec![],
            credential_schema: None,
        };
        unsigned.issue(issuer_key, &self.updated_at)
    }

    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    fn ensure_allocated(&self, index: usize) -> Result<()> {
        if !self.allocated.contains(&index) {
            return Err(CommonsError::InvalidInput(format!(
                "status index {index} has not been allocated"
            )));
        }
        Ok(())
    }
}

fn format_time(value: OffsetDateTime) -> Result<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| CommonsError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-08-02T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_compressed_bitstring() {
        let mut list = StatusList::new(
            "https://identity.example/status/2026-08",
            "did:webvh:demo:identity.example",
            StatusPurpose::Revocation,
            MIN_STATUS_ENTRIES,
            now(),
        )
        .unwrap();
        let first = list.allocate().unwrap();
        let second = list.allocate().unwrap();
        list.set(second, true, now()).unwrap();
        let decoded = StatusList::decode_list(&list.encoded_list().unwrap(), list.size).unwrap();
        assert_eq!(decoded, list.bits);
        assert!(!list.is_listed(first).unwrap());
        assert!(list.is_listed(second).unwrap());
    }

    #[test]
    fn stale_status_is_not_reported_as_active() {
        let mut list = StatusList::new(
            "https://identity.example/status/2026-08",
            "did:webvh:demo:identity.example",
            StatusPurpose::Revocation,
            MIN_STATUS_ENTRIES,
            now(),
        )
        .unwrap();
        let index = list.allocate().unwrap();
        let assessment = list
            .assess(index, Duration::hours(24), now() + Duration::hours(36))
            .unwrap();
        assert!(matches!(
            assessment,
            StatusAssessment::CurrentStatusUnknown { .. }
        ));
    }

    #[test]
    fn future_status_is_not_reported_as_active() {
        let mut list = StatusList::new(
            "https://identity.example/status/future",
            "did:webvh:demo:identity.example",
            StatusPurpose::Revocation,
            MIN_STATUS_ENTRIES,
            now() + Duration::hours(1),
        )
        .unwrap();
        let index = list.allocate().unwrap();
        assert!(matches!(
            list.assess(index, Duration::hours(24), now()).unwrap(),
            StatusAssessment::CurrentStatusUnknown { age_seconds, .. } if age_seconds < 0
        ));
    }

    #[test]
    fn signed_heartbeat_keeps_an_unchanged_list_fresh() {
        let mut list = StatusList::new(
            "https://identity.example/status/2026-08",
            "did:webvh:demo:identity.example",
            StatusPurpose::Revocation,
            MIN_STATUS_ENTRIES,
            now(),
        )
        .unwrap();
        let index = list.allocate().unwrap();
        list.touch(now() + Duration::hours(23)).unwrap();
        assert!(matches!(
            list.assess(index, Duration::hours(24), now() + Duration::hours(36))
                .unwrap(),
            StatusAssessment::Active { .. }
        ));
    }

    #[test]
    fn status_list_is_a_signed_vc() {
        let list = StatusList::new(
            "https://identity.example/status/2026-08",
            "did:webvh:demo:identity.example",
            StatusPurpose::Revocation,
            MIN_STATUS_ENTRIES,
            now(),
        )
        .unwrap();
        let key = SigningKeyMaterial::generate();
        let credential = list.as_credential(&key, Duration::days(2)).unwrap();
        credential
            .verify_with_issuer_key(&key.public_key_multibase(), now() + Duration::hours(1))
            .unwrap();
    }

    #[test]
    fn revocation_is_permanent_but_suspension_can_be_cleared() {
        let mut revoked = StatusList::new(
            "https://identity.example/status/revoked",
            "did:webvh:demo:identity.example",
            StatusPurpose::Revocation,
            MIN_STATUS_ENTRIES,
            now(),
        )
        .unwrap();
        let index = revoked.allocate().unwrap();
        revoked.set(index, true, now()).unwrap();
        assert!(revoked.set(index, false, now()).is_err());

        let mut suspended = StatusList::new(
            "https://identity.example/status/suspended",
            "did:webvh:demo:identity.example",
            StatusPurpose::Suspension,
            MIN_STATUS_ENTRIES,
            now(),
        )
        .unwrap();
        let index = suspended.allocate().unwrap();
        suspended.set(index, true, now()).unwrap();
        suspended.set(index, false, now()).unwrap();
        assert!(!suspended.is_listed(index).unwrap());
    }
}
