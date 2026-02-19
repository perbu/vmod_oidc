use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::OidcError;

pub(crate) const SESSION_COOKIE_PREFIX: &str = "v1.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StateCookie {
    pub(crate) state: String,
    pub(crate) nonce: String,
    pub(crate) exp: u64,
    pub(crate) return_to: String,
}

pub(crate) struct CookieCipher {
    cipher: Aes256Gcm,
}

impl CookieCipher {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new((&key).into()),
        }
    }

    pub(crate) fn encrypt_json<T: Serialize>(&self, value: &T) -> Result<String, OidcError> {
        let payload = serde_json::to_vec(value)?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
            .map_err(|_| OidcError::Crypto)?;

        let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        Ok(format!(
            "{SESSION_COOKIE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(out)
        ))
    }

    pub(crate) fn decrypt_json<T: DeserializeOwned>(&self, value: &str) -> Result<T, OidcError> {
        let encoded = value
            .strip_prefix(SESSION_COOKIE_PREFIX)
            .ok_or(OidcError::Crypto)?;
        let raw = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| OidcError::Crypto)?;

        if raw.len() < 12 + 16 {
            return Err(OidcError::Crypto);
        }

        let (nonce, ciphertext) = raw.split_at(12);
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| OidcError::Crypto)?;

        Ok(serde_json::from_slice(&plaintext)?)
    }
}

pub(crate) fn decode_cookie_secret(secret: &str) -> Result<[u8; 32], OidcError> {
    let value = secret.trim();

    // Explicit format prefix removes all ambiguity.
    if let Some(hex_str) = value.strip_prefix("hex:") {
        return decode_cookie_secret_bytes(
            &hex::decode(hex_str).map_err(|_| {
                OidcError::InvalidConfig("cookie_secret: invalid hex after 'hex:' prefix".into())
            })?,
        );
    }
    if let Some(b64_str) = value.strip_prefix("base64:") {
        return decode_cookie_secret_bytes(
            &STANDARD
                .decode(b64_str)
                .or_else(|_| STANDARD_NO_PAD.decode(b64_str))
                .map_err(|_| {
                    OidcError::InvalidConfig(
                        "cookie_secret: invalid base64 after 'base64:' prefix".into(),
                    )
                })?,
        );
    }
    if let Some(b64url_str) = value.strip_prefix("base64url:") {
        return decode_cookie_secret_bytes(
            &URL_SAFE
                .decode(b64url_str)
                .or_else(|_| URL_SAFE_NO_PAD.decode(b64url_str))
                .map_err(|_| {
                    OidcError::InvalidConfig(
                        "cookie_secret: invalid base64url after 'base64url:' prefix".into(),
                    )
                })?,
        );
    }

    // No prefix: auto-detect, but reject if ambiguous.
    let decoders: &[(&str, Option<Vec<u8>>)] = &[
        ("hex", hex::decode(value).ok()),
        ("base64", STANDARD.decode(value).ok()),
        ("base64url", URL_SAFE.decode(value).ok()),
        ("base64", STANDARD_NO_PAD.decode(value).ok()),
        ("base64url", URL_SAFE_NO_PAD.decode(value).ok()),
    ];

    let mut first_match: Option<(&str, Vec<u8>)> = None;
    for (name, candidate) in decoders {
        if let Some(bytes) = candidate
            && bytes.len() == 32
        {
            if let Some((prev_name, ref prev_bytes)) = first_match {
                if prev_bytes != bytes {
                    return Err(OidcError::InvalidConfig(format!(
                        "cookie_secret is ambiguous: valid as both {prev_name} and {name} \
                         with different results. Use an explicit prefix (e.g. '{prev_name}:' \
                         or '{name}:')"
                    )));
                }
            } else {
                first_match = Some((name, bytes.clone()));
            }
        }
    }

    if let Some((_name, bytes)) = first_match {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    Err(OidcError::InvalidConfig(
        "cookie_secret must decode to exactly 32 bytes (hex/base64/base64url). \
         You may use a prefix (hex:, base64:, base64url:) to specify the format."
            .to_string(),
    ))
}

fn decode_cookie_secret_bytes(bytes: &[u8]) -> Result<[u8; 32], OidcError> {
    if bytes.len() != 32 {
        return Err(OidcError::InvalidConfig(format!(
            "cookie_secret must decode to exactly 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    const TEST_SECRET_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn decode_cookie_secret_with_hex_prefix() {
        let key = decode_cookie_secret(
            "hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(
            key,
            hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn decode_cookie_secret_with_base64_prefix() {
        // 32 bytes encoded as standard base64
        let raw = [0xABu8; 32];
        let encoded = STANDARD.encode(raw);
        let key = decode_cookie_secret(&format!("base64:{encoded}")).unwrap();
        assert_eq!(key, raw);
    }

    #[test]
    fn decode_cookie_secret_with_base64url_prefix() {
        let raw = [0xCDu8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(raw);
        let key = decode_cookie_secret(&format!("base64url:{encoded}")).unwrap();
        assert_eq!(key, raw);
    }

    #[test]
    fn decode_cookie_secret_prefix_wrong_length_rejected() {
        // 16 bytes hex = 32 hex chars, but decodes to only 16 bytes
        let err = decode_cookie_secret("hex:0123456789abcdef0123456789abcdef").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn decode_cookie_secret_prefix_invalid_encoding_rejected() {
        let err = decode_cookie_secret("hex:not-valid-hex!!").unwrap_err();
        assert!(err.to_string().contains("invalid hex"));

        let err = decode_cookie_secret("base64:not valid base64!!!").unwrap_err();
        assert!(err.to_string().contains("invalid base64"));

        let err = decode_cookie_secret("base64url:not valid base64!!!").unwrap_err();
        assert!(err.to_string().contains("invalid base64url"));
    }

    #[test]
    fn decode_cookie_secret_unprefixed_hex_still_works() {
        // Backward compat: plain 64-char hex string
        let key = decode_cookie_secret(TEST_SECRET_HEX).unwrap();
        assert_eq!(key, hex::decode(TEST_SECRET_HEX).unwrap().as_slice());
    }

    #[test]
    fn decode_cookie_secret_unprefixed_base64_still_works() {
        let raw = [0x42u8; 32];
        let encoded = STANDARD.encode(raw);
        let key = decode_cookie_secret(&encoded).unwrap();
        assert_eq!(key, raw);
    }
}
