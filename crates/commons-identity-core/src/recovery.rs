use std::collections::BTreeMap;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    crypto::{canonicalize, sha256},
    error::{CommonsError, Result},
    presentation::ConsentReceipt,
    vault::IdentityVault,
};

const RECOVERY_MAGIC: &str = "commons-identity-recovery-kit";
const ARCHIVE_MAGIC: &str = "commons-identity-archive";
const PACKAGE_VERSION: &str = "1";
const XCHACHA_ALGORITHM: &str = "XChaCha20-Poly1305-IETF";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParameters {
    pub algorithm: String,
    pub version: u32,
    pub memory_kib: u32,
    pub passes: u32,
    pub parallelism: u32,
    pub output_bytes: u32,
    pub passphrase_encoding: String,
    pub passphrase_normalization: String,
}

impl Default for KdfParameters {
    fn default() -> Self {
        Self {
            algorithm: "Argon2id".into(),
            version: 0x13,
            memory_kib: 262_144,
            passes: 3,
            parallelism: 1,
            output_bytes: 32,
            passphrase_encoding: "UTF-8".into(),
            // Normalizing passphrases can make two visually different secrets equal.
            // CI archives preserve the exact UTF-8 byte sequence instead.
            passphrase_normalization: "none".into(),
        }
    }
}

impl KdfParameters {
    fn validate(&self) -> Result<()> {
        if self.algorithm != "Argon2id"
            || self.version != 0x13
            || self.output_bytes != 32
            || self.passphrase_encoding != "UTF-8"
            || self.passphrase_normalization != "none"
        {
            return Err(CommonsError::UnsupportedFormat(
                "unsupported Recovery Kit KDF profile".into(),
            ));
        }
        if !(8_192..=1_048_576).contains(&self.memory_kib)
            || !(1..=10).contains(&self.passes)
            || !(1..=16).contains(&self.parallelism)
        {
            return Err(CommonsError::InvalidInput(
                "KDF parameters are outside safe implementation bounds".into(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn test_fast() -> Self {
        Self {
            memory_kib: 8_192,
            passes: 1,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedPackage {
    magic: String,
    version: String,
    kdf: KdfParameters,
    salt: String,
    aead: String,
    nonce: String,
    ciphertext: String,
    checksum: String,
}

impl EncryptedPackage {
    fn encrypt<T: Serialize>(
        magic: &str,
        value: &T,
        passphrase: &str,
        parameters: KdfParameters,
    ) -> Result<Self> {
        validate_passphrase(passphrase)?;
        parameters.validate()?;
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = derive_key(passphrase, &salt, &parameters)?;
        let plaintext = Zeroizing::new(to_cbor(value)?);
        let aad = format!("{magic}\0{PACKAGE_VERSION}\0{XCHACHA_ALGORITHM}");
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|error| CommonsError::Recovery(error.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CommonsError::Recovery("Recovery Kit encryption failed".into()))?;
        let mut package = Self {
            magic: magic.into(),
            version: PACKAGE_VERSION.into(),
            kdf: parameters,
            salt: URL_SAFE_NO_PAD.encode(salt),
            aead: XCHACHA_ALGORITHM.into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            checksum: String::new(),
        };
        package.checksum = package.calculate_checksum()?;
        Ok(package)
    }

    fn decrypt<T: DeserializeOwned>(&self, expected_magic: &str, passphrase: &str) -> Result<T> {
        validate_passphrase(passphrase)?;
        self.validate_header(expected_magic)?;
        let calculated = self.calculate_checksum()?;
        if calculated
            .as_bytes()
            .ct_eq(self.checksum.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(CommonsError::Recovery(
                "Recovery Kit integrity checksum does not match".into(),
            ));
        }
        let salt = decode_exact::<16>(&self.salt, "salt")?;
        let nonce = decode_exact::<24>(&self.nonce, "nonce")?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|_| CommonsError::Recovery("ciphertext is not valid base64url".into()))?;
        let key = derive_key(passphrase, &salt, &self.kdf)?;
        let aad = format!("{}\0{}\0{}", self.magic, self.version, self.aead);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|error| CommonsError::Recovery(error.to_string()))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| {
                    CommonsError::Recovery("wrong passphrase or corrupted Recovery Kit".into())
                })?,
        );
        from_cbor(plaintext.as_ref())
    }

    fn validate_header(&self, expected_magic: &str) -> Result<()> {
        if self.magic != expected_magic || self.version != PACKAGE_VERSION {
            return Err(CommonsError::UnsupportedFormat(format!(
                "expected {expected_magic} version {PACKAGE_VERSION}"
            )));
        }
        if self.aead != XCHACHA_ALGORITHM {
            return Err(CommonsError::UnsupportedFormat(format!(
                "unsupported archive AEAD: {}",
                self.aead
            )));
        }
        self.kdf.validate()
    }

    fn calculate_checksum(&self) -> Result<String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ChecksumInput<'a> {
            magic: &'a str,
            version: &'a str,
            kdf: &'a KdfParameters,
            salt: &'a str,
            aead: &'a str,
            nonce: &'a str,
            ciphertext: &'a str,
        }
        let input = ChecksumInput {
            magic: &self.magic,
            version: &self.version,
            kdf: &self.kdf,
            salt: &self.salt,
            aead: &self.aead,
            nonce: &self.nonce,
            ciphertext: &self.ciphertext,
        };
        Ok(hex::encode(sha256(&canonicalize(&input)?)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverySnapshot {
    pub vault_format_version: String,
    pub vault: IdentityVault,
    pub latest_snapshot_reference: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKit(EncryptedPackage);

impl RecoveryKit {
    pub fn create(snapshot: &RecoverySnapshot, passphrase: &str) -> Result<Self> {
        Ok(Self(EncryptedPackage::encrypt(
            RECOVERY_MAGIC,
            snapshot,
            passphrase,
            KdfParameters::default(),
        )?))
    }

    #[cfg(test)]
    fn create_fast(snapshot: &RecoverySnapshot, passphrase: &str) -> Result<Self> {
        Ok(Self(EncryptedPackage::encrypt(
            RECOVERY_MAGIC,
            snapshot,
            passphrase,
            KdfParameters::test_fast(),
        )?))
    }

    pub fn open(&self, passphrase: &str) -> Result<RecoverySnapshot> {
        self.0.decrypt(RECOVERY_MAGIC, passphrase)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_cbor(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let kit: Self = from_cbor(bytes)?;
        kit.0.validate_header(RECOVERY_MAGIC)?;
        Ok(kit)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivePayload {
    pub archive_version: String,
    pub vault: IdentityVault,
    pub credential_formats: Vec<String>,
    pub consent_receipts: Vec<ConsentReceipt>,
    pub schema_snapshots: BTreeMap<String, Value>,
    pub resolver_cache: BTreeMap<String, Value>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonsIdentityArchive(EncryptedPackage);

impl CommonsIdentityArchive {
    pub fn create(payload: &ArchivePayload, passphrase: &str) -> Result<Self> {
        Ok(Self(EncryptedPackage::encrypt(
            ARCHIVE_MAGIC,
            payload,
            passphrase,
            KdfParameters::default(),
        )?))
    }

    #[cfg(test)]
    fn create_fast(payload: &ArchivePayload, passphrase: &str) -> Result<Self> {
        Ok(Self(EncryptedPackage::encrypt(
            ARCHIVE_MAGIC,
            payload,
            passphrase,
            KdfParameters::test_fast(),
        )?))
    }

    pub fn open(&self, passphrase: &str) -> Result<ArchivePayload> {
        self.0.decrypt(ARCHIVE_MAGIC, passphrase)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_cbor(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let archive: Self = from_cbor(bytes)?;
        archive.0.validate_header(ARCHIVE_MAGIC)?;
        Ok(archive)
    }
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; 16],
    parameters: &KdfParameters,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(
        parameters.memory_kib,
        parameters.passes,
        parameters.parallelism,
        Some(parameters.output_bytes as usize),
    )
    .map_err(|error| CommonsError::Recovery(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, output.as_mut())
        .map_err(|error| CommonsError::Recovery(error.to_string()))?;
    Ok(output)
}

fn validate_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.len() < 12 {
        return Err(CommonsError::InvalidInput(
            "Recovery Kit passphrase must contain at least 12 UTF-8 bytes".into(),
        ));
    }
    if passphrase.len() > 1_024 {
        return Err(CommonsError::InvalidInput(
            "Recovery Kit passphrase is too long".into(),
        ));
    }
    Ok(())
}

fn decode_exact<const N: usize>(encoded: &str, field: &str) -> Result<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CommonsError::Recovery(format!("{field} is not valid base64url")))?
        .try_into()
        .map_err(|_| CommonsError::Recovery(format!("{field} has an invalid length")))
}

fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    ciborium::into_writer(value, &mut output)
        .map_err(|error| CommonsError::Serialization(error.to_string()))?;
    Ok(output)
}

fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|error| CommonsError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::IdentityVault;
    use time::OffsetDateTime;

    fn timestamp() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-08-02T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    }

    fn snapshot() -> RecoverySnapshot {
        RecoverySnapshot {
            vault_format_version: "1".into(),
            vault: IdentityVault::create("Koichi's Mac", timestamp()).unwrap(),
            latest_snapshot_reference: None,
            created_at: "2026-08-02T00:00:00Z".into(),
        }
    }

    #[test]
    fn recovery_kit_round_trips_and_rejects_wrong_passphrase() {
        let kit = RecoveryKit::create_fast(&snapshot(), "a strong passphrase").unwrap();
        let bytes = kit.to_bytes().unwrap();
        let imported = RecoveryKit::from_bytes(&bytes).unwrap();
        let restored = imported.open("a strong passphrase").unwrap();
        assert_eq!(restored.vault_format_version, "1");
        assert!(imported.open("the wrong passphrase").is_err());
    }

    #[test]
    fn archive_round_trips_between_independent_instances() {
        let payload = ArchivePayload {
            archive_version: "1".into(),
            vault: snapshot().vault,
            credential_formats: vec!["application/vc".into()],
            consent_receipts: vec![],
            schema_snapshots: BTreeMap::new(),
            resolver_cache: BTreeMap::new(),
            created_at: "2026-08-02T00:00:00Z".into(),
        };
        let archive = CommonsIdentityArchive::create_fast(&payload, "a strong passphrase").unwrap();
        let other_implementation_boundary =
            CommonsIdentityArchive::from_bytes(&archive.to_bytes().unwrap()).unwrap();
        let restored = other_implementation_boundary
            .open("a strong passphrase")
            .unwrap();
        assert_eq!(restored.archive_version, "1");
    }
}
