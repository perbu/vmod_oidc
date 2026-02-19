use reqwest::blocking::Client;
use reqwest::header::CACHE_CONTROL;
use serde::Deserialize;
use std::collections::HashMap;

use crate::OidcError;
use crate::helpers::now_secs;

const DEFAULT_JWKS_MAX_AGE_SECS: u64 = 300;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DiscoveryDocument {
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    #[serde(default)]
    pub(crate) id_token: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct JwksCache {
    keyed: HashMap<String, RsaKeyMaterial>,
    unkeyed: Vec<RsaKeyMaterial>,
    total_keys: usize,
    pub(crate) expires_at: u64,
    pub(crate) refresh_failures: u32,
    pub(crate) backoff_until: u64,
}

impl JwksCache {
    pub(crate) fn lookup(&self, kid: Option<&str>) -> Option<RsaKeyMaterial> {
        match kid {
            Some(kid) => self.keyed.get(kid).cloned(),
            None => {
                if self.total_keys == 1 {
                    self.unkeyed
                        .first()
                        .cloned()
                        .or_else(|| self.keyed.values().next().cloned())
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RsaKeyMaterial {
    pub(crate) n: String,
    pub(crate) e: String,
}

pub(crate) fn fetch_discovery(
    client: &Client,
    discovery_url: &str,
) -> Result<DiscoveryDocument, OidcError> {
    let response = client.get(discovery_url).send()?.error_for_status()?;
    let discovery: DiscoveryDocument = response.json()?;

    if discovery.issuer.trim().is_empty()
        || discovery.authorization_endpoint.trim().is_empty()
        || discovery.token_endpoint.trim().is_empty()
        || discovery.jwks_uri.trim().is_empty()
    {
        return Err(OidcError::InvalidConfig(
            "discovery document is missing mandatory fields".to_string(),
        ));
    }

    Ok(discovery)
}

pub(crate) fn fetch_jwks_cache(
    client: &Client,
    jwks_uri: &str,
) -> Result<JwksCache, OidcError> {
    let response = client.get(jwks_uri).send()?.error_for_status()?;
    let max_age = response
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_max_age)
        .unwrap_or(DEFAULT_JWKS_MAX_AGE_SECS);

    let body: JwksDocument = response.json()?;

    let mut keyed = HashMap::new();
    let mut unkeyed = Vec::new();

    for key in body.keys {
        if key.kty != "RSA" {
            continue;
        }

        if let Some(alg) = key.alg.as_deref()
            && alg != "RS256"
        {
            continue;
        }

        if let Some(u) = key.key_use.as_deref()
            && u != "sig"
        {
            continue;
        }

        let n = match key.n {
            Some(v) if !v.trim().is_empty() => v,
            _ => continue,
        };
        let e = match key.e {
            Some(v) if !v.trim().is_empty() => v,
            _ => continue,
        };

        let material = RsaKeyMaterial { n, e };
        match key.kid {
            Some(kid) if !kid.trim().is_empty() => {
                keyed.insert(kid, material);
            }
            _ => unkeyed.push(material),
        }
    }

    let total_keys = keyed.len() + unkeyed.len();
    if total_keys == 0 {
        return Err(OidcError::InvalidToken(
            "jwks does not contain usable RSA keys".to_string(),
        ));
    }

    Ok(JwksCache {
        keyed,
        unkeyed,
        total_keys,
        expires_at: now_secs() + max_age,
        refresh_failures: 0,
        backoff_until: 0,
    })
}

fn parse_max_age(cache_control: &str) -> Option<u64> {
    cache_control
        .split(',')
        .map(str::trim)
        .find_map(|directive| {
            directive
                .strip_prefix("max-age=")
                .and_then(|val| val.parse::<u64>().ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_max_age_extracts_correct_value() {
        assert_eq!(parse_max_age("max-age=300"), Some(300));
        assert_eq!(parse_max_age("public, max-age=120"), Some(120));
        assert_eq!(parse_max_age("no-cache, no-store"), None);
        assert_eq!(parse_max_age("max-age=0"), Some(0));
        assert_eq!(parse_max_age(""), None);
        assert_eq!(parse_max_age("max-age=abc"), None);
        assert_eq!(parse_max_age("s-maxage=300"), None);
    }
}
