use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use multibase::Base;
use rand::{CryptoRng, RngCore, rngs::OsRng};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CommonsError, Result};

type HmacSha256 = Hmac<Sha256>;

/// A fixed-size secret that is redacted from `Debug` and zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    pub fn random() -> Self {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret32([REDACTED])")
    }
}

impl Serialize for Secret32 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0));
        serializer.serialize_str(encoded.as_str())
    }
}

impl<'de> Deserialize<'de> for Secret32 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded.as_bytes())
                .map_err(D::Error::custom)?,
        );
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("secret must contain exactly 32 bytes"))?;
        Ok(Self(bytes))
    }
}

/// Ed25519 signing material kept in the holder or authority vault.
#[derive(Clone, Serialize, Deserialize)]
pub struct SigningKeyMaterial {
    secret: Secret32,
}

impl fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKeyMaterial")
            .field("public_key_multibase", &self.public_key_multibase())
            .finish_non_exhaustive()
    }
}

impl SigningKeyMaterial {
    pub fn generate() -> Self {
        Self {
            secret: Secret32::random(),
        }
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            secret: Secret32::from_bytes(secret),
        }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(self.secret.expose())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }

    /// Ed25519 public key encoded with the multicodec prefix and base58btc.
    pub fn public_key_multibase(&self) -> String {
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&[0xed, 0x01]);
        bytes.extend_from_slice(self.verifying_key().as_bytes());
        multibase::encode(Base::Base58Btc, bytes)
    }

    pub fn did_key(&self) -> String {
        format!("did:key:{}", self.public_key_multibase())
    }

    pub fn verification_method(&self) -> String {
        let did = self.did_key();
        format!("{did}#{}", self.public_key_multibase())
    }

    pub fn sign_multibase(&self, message: &[u8]) -> String {
        let signature = self.signing_key().sign(message);
        multibase::encode(Base::Base58Btc, signature.to_bytes())
    }

    pub fn verify_multibase(public_key: &str, message: &[u8], signature: &str) -> Result<()> {
        let verifying_key = Self::validate_public_key_multibase(public_key)?;
        let (_, signature_bytes) = multibase::decode(signature)
            .map_err(|error| CommonsError::Crypto(format!("invalid proof multibase: {error}")))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|error| CommonsError::Crypto(error.to_string()))?;
        verifying_key
            .verify(message, &signature)
            .map_err(|_| CommonsError::Crypto("signature did not verify".to_string()))
    }

    pub fn validate_public_key_multibase(public_key: &str) -> Result<VerifyingKey> {
        let (base, public_bytes) = multibase::decode(public_key)
            .map_err(|error| CommonsError::Crypto(format!("invalid public multibase: {error}")))?;
        if base != Base::Base58Btc {
            return Err(CommonsError::Crypto(
                "Ed25519 multikey must use base58btc".to_string(),
            ));
        }
        if public_bytes.get(..2) != Some(&[0xed, 0x01]) {
            return Err(CommonsError::Crypto(
                "public key is not an Ed25519 multikey".to_string(),
            ));
        }
        let key_bytes: [u8; 32] = public_bytes[2..]
            .try_into()
            .map_err(|_| CommonsError::Crypto("invalid Ed25519 public key length".to_string()))?;
        VerifyingKey::from_bytes(&key_bytes)
            .map_err(|error| CommonsError::Crypto(error.to_string()))
    }

    pub fn public_key_from_verification_method(method: &str) -> Result<String> {
        let fragment = method
            .rsplit_once('#')
            .map(|(_, fragment)| fragment)
            .ok_or_else(|| CommonsError::Crypto("verification method lacks a fragment".into()))?;
        if !fragment.starts_with('z') {
            return Err(CommonsError::Crypto(
                "verification method fragment is not a multikey".into(),
            ));
        }
        Self::validate_public_key_multibase(fragment)?;
        Ok(fragment.to_string())
    }
}

/// Per-device signing and X25519 encryption material.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceKeyMaterial {
    pub signing: SigningKeyMaterial,
    encryption_secret: Secret32,
}

impl fmt::Debug for DeviceKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceKeyMaterial")
            .field("signing", &self.signing)
            .field("encryption_public_key", &self.encryption_public_key())
            .finish_non_exhaustive()
    }
}

impl DeviceKeyMaterial {
    pub fn generate() -> Self {
        Self {
            signing: SigningKeyMaterial::generate(),
            encryption_secret: Secret32::random(),
        }
    }

    pub fn encryption_public_key(&self) -> String {
        let secret = StaticSecret::from(*self.encryption_secret.expose());
        let public = X25519PublicKey::from(&secret);
        let mut bytes = Vec::with_capacity(34);
        // x25519-pub multicodec: 0xec 0x01
        bytes.extend_from_slice(&[0xec, 0x01]);
        bytes.extend_from_slice(public.as_bytes());
        multibase::encode(Base::Base58Btc, bytes)
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_multibase(data: &[u8]) -> String {
    multibase::encode(Base::Base58Btc, sha256(data))
}

pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|error| CommonsError::Serialization(error.to_string()))
}

pub fn random_urlsafe<R>(rng: &mut R, byte_count: usize) -> String
where
    R: CryptoRng + RngCore,
{
    let mut bytes = vec![0_u8; byte_count];
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn pseudonym(secret: &Secret32, domain: &str) -> Result<String> {
    if domain.trim().is_empty() {
        return Err(CommonsError::InvalidInput(
            "pseudonym domain cannot be empty".into(),
        ));
    }
    let mut mac = HmacSha256::new_from_slice(secret.expose())
        .map_err(|error| CommonsError::Crypto(error.to_string()))?;
    mac.update(b"commons-identity/1:pseudonym\0");
    mac.update(domain.as_bytes());
    let digest = mac.finalize().into_bytes();
    Ok(format!("ci_nym_{}", URL_SAFE_NO_PAD.encode(&digest[..20])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_round_trip_and_debug_redaction() {
        let key = SigningKeyMaterial::generate();
        let message = b"context separated identity";
        let signature = key.sign_multibase(message);
        SigningKeyMaterial::verify_multibase(&key.public_key_multibase(), message, &signature)
            .expect("signature should verify");
        assert!(!format!("{key:?}").contains(&URL_SAFE_NO_PAD.encode(key.secret.expose())));
    }

    #[test]
    fn pseudonyms_are_stable_only_inside_one_domain() {
        let secret = Secret32::random();
        let first = pseudonym(&secret, "archive.example").unwrap();
        let again = pseudonym(&secret, "archive.example").unwrap();
        let other = pseudonym(&secret, "attendance.example").unwrap();
        assert_eq!(first, again);
        assert_ne!(first, other);
    }
}
