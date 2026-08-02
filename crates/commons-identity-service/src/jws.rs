use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use commons_identity_core::SigningKeyMaterial;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::ApiError;

pub fn sign_request_object<T: Serialize>(
    payload: &T,
    key: &SigningKeyMaterial,
) -> Result<String, ApiError> {
    sign_request_object_with_kid(payload, key, &key.verification_method())
}

pub fn sign_request_object_with_kid<T: Serialize>(
    payload: &T,
    key: &SigningKeyMaterial,
    kid: &str,
) -> Result<String, ApiError> {
    let header = json!({
        "alg": "EdDSA",
        "typ": "oauth-authz-req+jwt",
        "kid": kid,
    });
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?);
    let signing_input = format!("{header}.{payload}");
    let (_, signature) = multibase::decode(key.sign_multibase(signing_input.as_bytes()))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

pub fn verify_request_object<T: DeserializeOwned>(
    compact: &str,
    public_key_multibase: &str,
) -> Result<T, ApiError> {
    verify_request_object_with_kid(compact, public_key_multibase, None)
}

pub fn verify_request_object_with_kid<T: DeserializeOwned>(
    compact: &str,
    public_key_multibase: &str,
    expected_kid: Option<&str>,
) -> Result<T, ApiError> {
    let mut parts = compact.split('.');
    let header = parts
        .next()
        .ok_or_else(|| ApiError::invalid("JWS header missing"))?;
    let payload = parts
        .next()
        .ok_or_else(|| ApiError::invalid("JWS payload missing"))?;
    let signature = parts
        .next()
        .ok_or_else(|| ApiError::invalid("JWS signature missing"))?;
    if parts.next().is_some() {
        return Err(ApiError::invalid("JWS contains too many segments"));
    }
    let header_value: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header)
            .map_err(|_| ApiError::invalid("JWS header is not base64url"))?,
    )?;
    if header_value.get("alg").and_then(|value| value.as_str()) != Some("EdDSA")
        || header_value.get("typ").and_then(|value| value.as_str()) != Some("oauth-authz-req+jwt")
    {
        return Err(ApiError::invalid(
            "request object must use EdDSA and oauth-authz-req+jwt",
        ));
    }
    if let Some(expected_kid) = expected_kid {
        if header_value.get("kid").and_then(|value| value.as_str()) != Some(expected_kid) {
            return Err(ApiError::unauthorized(
                "request object kid is not authorized by the verifier DID",
            ));
        }
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ApiError::invalid("JWS signature is not base64url"))?;
    let signature = multibase::encode(multibase::Base::Base58Btc, signature);
    SigningKeyMaterial::verify_multibase(
        public_key_multibase,
        format!("{header}.{payload}").as_bytes(),
        &signature,
    )?;
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| ApiError::invalid("JWS payload is not base64url"))?,
    )
    .map_err(ApiError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies_request_object() {
        let key = SigningKeyMaterial::generate();
        let jwt = sign_request_object(&json!({"nonce": "fresh"}), &key).unwrap();
        let payload: serde_json::Value =
            verify_request_object(&jwt, &key.public_key_multibase()).unwrap();
        assert_eq!(payload["nonce"], "fresh");
    }
}
