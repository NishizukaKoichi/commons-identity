use std::path::Path;

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::{
    error::{CommonsError, Result},
    vault::IdentityVault,
};

const STORE_VERSION: &str = "1";

/// SQLite record store with independent AEAD encryption for every value.
///
/// SQLite intentionally contains only opaque identifiers, coarse record types,
/// nonces, and ciphertext. Secret fields and credentials are never queryable as
/// plaintext columns.
pub struct EncryptedRecordStore {
    connection: Connection,
}

impl EncryptedRecordStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        let store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        let store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<()> {
        self.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS ci_metadata (
               key TEXT PRIMARY KEY NOT NULL,
               value TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS encrypted_records (
               record_id TEXT PRIMARY KEY NOT NULL,
               record_type TEXT NOT NULL,
               nonce BLOB NOT NULL CHECK(length(nonce) = 24),
               ciphertext BLOB NOT NULL,
               updated_at TEXT NOT NULL
             ) STRICT;",
        )?;
        self.connection.execute(
            "INSERT INTO ci_metadata(key, value) VALUES ('store_version', ?1)
             ON CONFLICT(key) DO NOTHING",
            [STORE_VERSION],
        )?;
        let version: String = self.connection.query_row(
            "SELECT value FROM ci_metadata WHERE key = 'store_version'",
            [],
            |row| row.get(0),
        )?;
        if version != STORE_VERSION {
            return Err(CommonsError::UnsupportedFormat(format!(
                "encrypted record store version {version}"
            )));
        }
        Ok(())
    }

    pub fn put<T: Serialize>(
        &self,
        vault: &IdentityVault,
        record_id: &str,
        record_type: &str,
        value: &T,
        now: OffsetDateTime,
    ) -> Result<()> {
        validate_record_header(record_id, record_type)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(value)?);
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = record_aad(record_id, record_type);
        let cipher = XChaCha20Poly1305::new_from_slice(vault.vault_encryption_key())
            .map_err(|error| CommonsError::Storage(error.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CommonsError::Storage("record encryption failed".into()))?;
        let timestamp = now
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| CommonsError::Storage(error.to_string()))?;
        self.connection.execute(
            "INSERT INTO encrypted_records(record_id, record_type, nonce, ciphertext, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(record_id) DO UPDATE SET
               record_type = excluded.record_type,
               nonce = excluded.nonce,
               ciphertext = excluded.ciphertext,
               updated_at = excluded.updated_at",
            params![
                record_id,
                record_type,
                nonce.as_slice(),
                ciphertext,
                timestamp
            ],
        )?;
        Ok(())
    }

    pub fn get<T: DeserializeOwned>(
        &self,
        vault: &IdentityVault,
        record_id: &str,
        expected_type: &str,
    ) -> Result<T> {
        validate_record_header(record_id, expected_type)?;
        let row: Option<(String, Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT record_type, nonce, ciphertext
                 FROM encrypted_records WHERE record_id = ?1",
                [record_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (record_type, nonce, ciphertext) =
            row.ok_or_else(|| CommonsError::NotFound(record_id.into()))?;
        if record_type != expected_type {
            return Err(CommonsError::Storage(
                "record type does not match requested type".into(),
            ));
        }
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| CommonsError::Storage("record nonce has an invalid length".into()))?;
        let cipher = XChaCha20Poly1305::new_from_slice(vault.vault_encryption_key())
            .map_err(|error| CommonsError::Storage(error.to_string()))?;
        let aad = record_aad(record_id, expected_type);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| CommonsError::Storage("record authentication failed".into()))?,
        );
        serde_json::from_slice(plaintext.as_ref()).map_err(CommonsError::from)
    }

    pub fn delete(&self, record_id: &str) -> Result<bool> {
        if record_id.is_empty() || record_id.len() > 200 {
            return Err(CommonsError::InvalidInput(
                "invalid record identifier".into(),
            ));
        }
        Ok(self.connection.execute(
            "DELETE FROM encrypted_records WHERE record_id = ?1",
            [record_id],
        )? > 0)
    }

    pub fn record_count(&self) -> Result<usize> {
        self.connection
            .query_row("SELECT COUNT(*) FROM encrypted_records", [], |row| {
                row.get(0)
            })
            .map_err(CommonsError::from)
    }

    #[cfg(test)]
    fn raw_ciphertext(&self, record_id: &str) -> Result<Vec<u8>> {
        self.connection
            .query_row(
                "SELECT ciphertext FROM encrypted_records WHERE record_id = ?1",
                [record_id],
                |row| row.get(0),
            )
            .map_err(CommonsError::from)
    }
}

fn record_aad(record_id: &str, record_type: &str) -> String {
    format!("commons-identity-record\0{STORE_VERSION}\0{record_type}\0{record_id}")
}

fn validate_record_header(record_id: &str, record_type: &str) -> Result<()> {
    if record_id.trim().is_empty() || record_id.len() > 200 {
        return Err(CommonsError::InvalidInput(
            "invalid record identifier".into(),
        ));
    }
    if record_type.trim().is_empty()
        || record_type.len() > 80
        || !record_type
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(CommonsError::InvalidInput("invalid record type".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct PrivateRecord {
        legal_name: String,
        secret_note: String,
    }

    #[test]
    fn database_never_contains_plaintext_record_values() {
        let vault = IdentityVault::create("Mac", OffsetDateTime::UNIX_EPOCH).unwrap();
        let store = EncryptedRecordStore::in_memory().unwrap();
        let record = PrivateRecord {
            legal_name: "Example Legal Name".into(),
            secret_note: "never place this in a queryable column".into(),
        };
        store
            .put(
                &vault,
                "persona:example",
                "persona",
                &record,
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap();
        let raw = store.raw_ciphertext("persona:example").unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("Example Legal Name"));
        let restored: PrivateRecord = store.get(&vault, "persona:example", "persona").unwrap();
        assert_eq!(restored, record);
    }

    #[test]
    fn aad_prevents_record_swapping() {
        let vault = IdentityVault::create("Mac", OffsetDateTime::UNIX_EPOCH).unwrap();
        let store = EncryptedRecordStore::in_memory().unwrap();
        store
            .put(
                &vault,
                "one",
                "persona",
                &serde_json::json!({"value": 1}),
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap();
        assert!(
            store
                .get::<serde_json::Value>(&vault, "one", "credential")
                .is_err()
        );
    }
}
