use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rand::Rng;
use rand::distributions::Alphanumeric;
use reqwest::blocking::Client;
use reqwest::header::CACHE_CONTROL;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

const SESSION_COOKIE_PREFIX: &str = "v1.";
const DEFAULT_COOKIE_NAME: &str = "__oidc";
const DEFAULT_STATE_COOKIE_NAME: &str = "__oidc_state";
const DEFAULT_SCOPES: &str = "openid";
const DEFAULT_COOKIE_TTL_SECS: u64 = 3600;
const DEFAULT_STATE_COOKIE_TTL_SECS: u64 = 300;
const DEFAULT_JWKS_MAX_AGE_SECS: u64 = 300;
const MAX_RETURN_TO_LEN: usize = 2048;
const MAX_CLAIMS_BYTES: usize = 3072;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("invalid state")]
    InvalidState,
    #[error("crypto failure")]
    Crypto,
}

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub cookie_secret: String,
    pub cookie_name: String,
    pub state_cookie_name: String,
    pub cookie_ttl_secs: u64,
    pub state_cookie_ttl_secs: u64,
    pub cookie_secure: bool,
    pub scopes: String,
}

impl ProviderConfig {
    pub fn normalize(mut self) -> Result<Self, OidcError> {
        if self.discovery_url.trim().is_empty() {
            return Err(OidcError::InvalidConfig(
                "discovery_url is required".to_string(),
            ));
        }
        if self.client_id.trim().is_empty() {
            return Err(OidcError::InvalidConfig(
                "client_id is required".to_string(),
            ));
        }
        if self.client_secret.trim().is_empty() {
            return Err(OidcError::InvalidConfig(
                "client_secret is required".to_string(),
            ));
        }
        if self.redirect_uri.trim().is_empty() {
            return Err(OidcError::InvalidConfig(
                "redirect_uri is required".to_string(),
            ));
        }
        if self.cookie_secret.trim().is_empty() {
            return Err(OidcError::InvalidConfig(
                "cookie_secret is required".to_string(),
            ));
        }

        if self.cookie_name.trim().is_empty() {
            self.cookie_name = DEFAULT_COOKIE_NAME.to_string();
        }
        if self.state_cookie_name.trim().is_empty() {
            self.state_cookie_name = if self.cookie_name == DEFAULT_COOKIE_NAME {
                DEFAULT_STATE_COOKIE_NAME.to_string()
            } else {
                format!("{}_state", self.cookie_name)
            };
        }
        if self.scopes.trim().is_empty() {
            self.scopes = DEFAULT_SCOPES.to_string();
        }
        if self.cookie_ttl_secs == 0 {
            self.cookie_ttl_secs = DEFAULT_COOKIE_TTL_SECS;
        }
        if self.state_cookie_ttl_secs == 0 {
            self.state_cookie_ttl_secs = DEFAULT_STATE_COOKIE_TTL_SECS;
        }

        Ok(self)
    }
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            discovery_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            cookie_secret: String::new(),
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            state_cookie_name: DEFAULT_STATE_COOKIE_NAME.to_string(),
            cookie_ttl_secs: DEFAULT_COOKIE_TTL_SECS,
            state_cookie_ttl_secs: DEFAULT_STATE_COOKIE_TTL_SECS,
            cookie_secure: true,
            scopes: DEFAULT_SCOPES.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationStart {
    pub url: String,
    pub state_set_cookie: String,
}

pub struct Provider {
    config: ProviderConfig,
    client: Client,
    discovery: DiscoveryDocument,
    cookie_cipher: CookieCipher,
    jwks_cache: Mutex<JwksCache>,
}

impl Provider {
    pub fn new(config: ProviderConfig) -> Result<Self, OidcError> {
        let config = config.normalize()?;
        let cookie_key = decode_cookie_secret(&config.cookie_secret)?;

        let client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()?;

        let discovery = fetch_discovery(&client, &config.discovery_url)?;
        let jwks_cache = fetch_jwks_cache(&client, &discovery.jwks_uri)?;

        Ok(Self {
            config,
            client,
            discovery,
            cookie_cipher: CookieCipher::new(cookie_key),
            jwks_cache: Mutex::new(jwks_cache),
        })
    }

    pub fn authorization_url(
        &self,
        current_request_url: &str,
    ) -> Result<AuthorizationStart, OidcError> {
        let state = random_token(32);
        let nonce = random_token(32);
        let return_to = derive_return_to(current_request_url);

        let state_cookie = StateCookie {
            state: state.clone(),
            nonce,
            exp: now_secs() + self.config.state_cookie_ttl_secs,
            return_to,
        };

        let state_cookie_value = self.cookie_cipher.encrypt_json(&state_cookie)?;
        let state_set_cookie = build_set_cookie(
            &self.config.state_cookie_name,
            &state_cookie_value,
            self.config.state_cookie_ttl_secs,
            self.config.cookie_secure,
        );

        let mut auth_url = Url::parse(&self.discovery.authorization_endpoint)?;
        auth_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &self.config.scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &state_cookie.nonce);

        Ok(AuthorizationStart {
            url: auth_url.to_string(),
            state_set_cookie,
        })
    }

    pub fn callback_code(&self, callback_url: &str) -> String {
        query_param(callback_url, "code").unwrap_or_default()
    }

    pub fn callback_state(&self, callback_url: &str) -> String {
        query_param(callback_url, "state").unwrap_or_default()
    }

    pub fn callback_state_valid(&self, callback_url: &str, cookie_header: Option<&str>) -> bool {
        self.load_valid_state(callback_url, cookie_header).is_ok()
    }

    pub fn callback_redirect_target(
        &self,
        callback_url: &str,
        cookie_header: Option<&str>,
    ) -> String {
        self.load_valid_state(callback_url, cookie_header)
            .map(|state| validate_return_to(&state.return_to))
            .unwrap_or_else(|_| "/".to_string())
    }

    pub fn exchange_code_for_session(
        &self,
        code: &str,
        callback_url: &str,
        cookie_header: Option<&str>,
    ) -> String {
        self.exchange_code_for_session_result(code, callback_url, cookie_header)
            .unwrap_or_default()
    }

    pub fn session_valid(&self, cookie_header: Option<&str>) -> bool {
        self.load_session_claims(cookie_header).is_ok()
    }

    pub fn claim(&self, cookie_header: Option<&str>, name: &str) -> String {
        match self.load_session_claims(cookie_header) {
            Ok(claims) => match claims.get(name) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                Some(Value::Bool(v)) => v.to_string(),
                Some(Value::Array(v)) => serde_json::to_string(v).unwrap_or_default(),
                Some(Value::Object(v)) => serde_json::to_string(v).unwrap_or_default(),
                _ => String::new(),
            },
            Err(_) => String::new(),
        }
    }

    pub fn create_session_cookie_from_claims(&self, claims: &Value) -> Result<String, OidcError> {
        let bytes = serde_json::to_vec(claims)?;
        if bytes.len() > MAX_CLAIMS_BYTES {
            return Err(OidcError::InvalidToken(
                "serialized claims exceeds 3072 bytes".to_string(),
            ));
        }

        let value = self.cookie_cipher.encrypt_json(claims)?;
        Ok(build_set_cookie(
            &self.config.cookie_name,
            &value,
            self.config.cookie_ttl_secs,
            self.config.cookie_secure,
        ))
    }

    fn exchange_code_for_session_result(
        &self,
        code: &str,
        callback_url: &str,
        cookie_header: Option<&str>,
    ) -> Result<String, OidcError> {
        if code.trim().is_empty() {
            return Err(OidcError::InvalidToken(
                "missing authorization code".to_string(),
            ));
        }

        let state = self.load_valid_state(callback_url, cookie_header)?;
        let id_token = self.exchange_for_id_token(code)?;
        let claims = self.validate_id_token(&id_token, &state.nonce)?;

        self.create_session_cookie_from_claims(&claims)
    }

    fn exchange_for_id_token(&self, code: &str) -> Result<String, OidcError> {
        let response = self
            .client
            .post(&self.discovery.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
            ])
            .send()?;

        if !response.status().is_success() {
            return Err(OidcError::InvalidToken(format!(
                "token endpoint returned {}",
                response.status()
            )));
        }

        let token_response: TokenResponse = response.json()?;
        token_response
            .id_token
            .ok_or_else(|| OidcError::InvalidToken("token response missing id_token".to_string()))
    }

    fn validate_id_token(&self, id_token: &str, expected_nonce: &str) -> Result<Value, OidcError> {
        self.refresh_jwks_if_expired()?;

        let header = decode_header(id_token)?;
        if header.alg != Algorithm::RS256 {
            return Err(OidcError::InvalidToken(
                "only RS256 is supported in v1".to_string(),
            ));
        }

        let key = self.decoding_key_for_kid(header.kid.as_deref())?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.discovery.issuer.as_str()]);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.required_spec_claims = HashSet::from([
            "exp".to_string(),
            "iat".to_string(),
            "aud".to_string(),
            "iss".to_string(),
        ]);

        let token_data = decode::<Value>(id_token, &key, &validation)?;

        let nonce = token_data
            .claims
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| OidcError::InvalidToken("nonce claim missing".to_string()))?;
        let sub = token_data
            .claims
            .get("sub")
            .and_then(Value::as_str)
            .ok_or_else(|| OidcError::InvalidToken("sub claim missing".to_string()))?;

        if nonce != expected_nonce {
            return Err(OidcError::InvalidToken("nonce mismatch".to_string()));
        }
        if sub.is_empty() {
            return Err(OidcError::InvalidToken("sub claim missing".to_string()));
        }

        Ok(token_data.claims)
    }

    fn refresh_jwks_if_expired(&self) -> Result<(), OidcError> {
        let expired = {
            let cache = self
                .jwks_cache
                .lock()
                .map_err(|_| OidcError::Internal("jwks mutex poisoned".to_string()))?;
            now_secs() >= cache.expires_at
        };

        if expired {
            self.refresh_jwks(true)?;
        }

        Ok(())
    }

    fn refresh_jwks(&self, required_for_request: bool) -> Result<(), OidcError> {
        let now = now_secs();
        let prev_expires_at;
        {
            let cache = self
                .jwks_cache
                .lock()
                .map_err(|_| OidcError::Internal("jwks mutex poisoned".to_string()))?;

            if now < cache.backoff_until {
                return Err(OidcError::InvalidToken(
                    "jwks refresh in backoff window".to_string(),
                ));
            }

            if !required_for_request && now < cache.expires_at {
                return Ok(());
            }

            prev_expires_at = cache.expires_at;
        }

        match fetch_jwks_cache(&self.client, &self.discovery.jwks_uri) {
            Ok(new_cache) => {
                let mut cache = self
                    .jwks_cache
                    .lock()
                    .map_err(|_| OidcError::Internal("jwks mutex poisoned".to_string()))?;
                // Only update if no other thread refreshed while we were fetching.
                if cache.expires_at == prev_expires_at {
                    *cache = new_cache;
                }
                Ok(())
            }
            Err(err) => {
                let mut cache = self
                    .jwks_cache
                    .lock()
                    .map_err(|_| OidcError::Internal("jwks mutex poisoned".to_string()))?;
                // Only set backoff if no other thread refreshed successfully.
                if cache.expires_at == prev_expires_at {
                    let exponent = cmp::min(cache.refresh_failures, 6);
                    let backoff = 1u64 << exponent;
                    cache.refresh_failures = cache.refresh_failures.saturating_add(1);
                    cache.backoff_until = now_secs() + cmp::min(backoff, 60);
                }
                Err(err)
            }
        }
    }

    fn decoding_key_for_kid(&self, kid: Option<&str>) -> Result<DecodingKey, OidcError> {
        if let Some(key) = self.lookup_key(kid)? {
            return DecodingKey::from_rsa_components(&key.n, &key.e)
                .map_err(|e| OidcError::InvalidToken(format!("invalid jwk: {e}")));
        }

        self.refresh_jwks(true)?;

        if let Some(key) = self.lookup_key(kid)? {
            return DecodingKey::from_rsa_components(&key.n, &key.e)
                .map_err(|e| OidcError::InvalidToken(format!("invalid jwk: {e}")));
        }

        Err(OidcError::InvalidToken(
            "no matching jwk found for token kid".to_string(),
        ))
    }

    fn lookup_key(&self, kid: Option<&str>) -> Result<Option<RsaKeyMaterial>, OidcError> {
        let cache = self
            .jwks_cache
            .lock()
            .map_err(|_| OidcError::Internal("jwks mutex poisoned".to_string()))?;

        Ok(cache.lookup(kid))
    }

    fn load_valid_state(
        &self,
        callback_url: &str,
        cookie_header: Option<&str>,
    ) -> Result<StateCookie, OidcError> {
        let expected_state = self.callback_state(callback_url);
        if expected_state.is_empty() {
            return Err(OidcError::InvalidState);
        }

        let raw_state_cookie = cookie_value(cookie_header, &self.config.state_cookie_name)
            .ok_or(OidcError::InvalidState)?;

        let state: StateCookie = self.cookie_cipher.decrypt_json(&raw_state_cookie)?;
        if state.exp <= now_secs() {
            return Err(OidcError::InvalidState);
        }

        if state.state != expected_state {
            return Err(OidcError::InvalidState);
        }

        Ok(state)
    }

    fn load_session_claims(
        &self,
        cookie_header: Option<&str>,
    ) -> Result<Map<String, Value>, OidcError> {
        let raw_cookie = cookie_value(cookie_header, &self.config.cookie_name)
            .ok_or_else(|| OidcError::InvalidToken("session cookie missing".to_string()))?;
        let claims: Value = self.cookie_cipher.decrypt_json(&raw_cookie)?;
        let obj = claims
            .as_object()
            .ok_or_else(|| OidcError::InvalidToken("claims payload must be an object".to_string()))?
            .clone();

        let exp = obj
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or_else(|| OidcError::InvalidToken("exp claim missing".to_string()))?;

        if exp <= now_secs() as i64 {
            return Err(OidcError::InvalidToken("session expired".to_string()));
        }

        Ok(obj)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
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
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
}

#[derive(Debug, Clone)]
struct JwksCache {
    keyed: HashMap<String, RsaKeyMaterial>,
    unkeyed: Vec<RsaKeyMaterial>,
    total_keys: usize,
    expires_at: u64,
    refresh_failures: u32,
    backoff_until: u64,
}

impl JwksCache {
    fn lookup(&self, kid: Option<&str>) -> Option<RsaKeyMaterial> {
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
struct RsaKeyMaterial {
    n: String,
    e: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateCookie {
    state: String,
    nonce: String,
    exp: u64,
    return_to: String,
}

struct CookieCipher {
    cipher: Aes256Gcm,
}

impl CookieCipher {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new((&key).into()),
        }
    }

    fn encrypt_json<T: Serialize>(&self, value: &T) -> Result<String, OidcError> {
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

    fn decrypt_json<T: DeserializeOwned>(&self, value: &str) -> Result<T, OidcError> {
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

fn fetch_discovery(client: &Client, discovery_url: &str) -> Result<DiscoveryDocument, OidcError> {
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

fn fetch_jwks_cache(client: &Client, jwks_uri: &str) -> Result<JwksCache, OidcError> {
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

        if let Some(alg) = key.alg.as_deref() {
            if alg != "RS256" {
                continue;
            }
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

fn random_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn build_set_cookie(name: &str, value: &str, max_age_secs: u64, secure: bool) -> String {
    let mut out = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}");
    if secure {
        out.push_str("; Secure");
    }
    out
}

fn decode_cookie_secret(secret: &str) -> Result<[u8; 32], OidcError> {
    let value = secret.trim();

    let candidates = [
        hex::decode(value).ok(),
        STANDARD.decode(value).ok(),
        URL_SAFE.decode(value).ok(),
        STANDARD_NO_PAD.decode(value).ok(),
        URL_SAFE_NO_PAD.decode(value).ok(),
    ];

    for candidate in candidates.into_iter().flatten() {
        if candidate.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&candidate);
            return Ok(key);
        }
    }

    Err(OidcError::InvalidConfig(
        "cookie_secret must decode to exactly 32 bytes (hex/base64/base64url)".to_string(),
    ))
}

fn cookie_value(cookie_header: Option<&str>, cookie_name: &str) -> Option<String> {
    cookie_header.and_then(|cookie_header| {
        cookie_header.split(';').find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            if name == cookie_name {
                Some(value.to_string())
            } else {
                None
            }
        })
    })
}

fn query_param(url_or_path: &str, key: &str) -> Option<String> {
    let parsed = parse_url_or_path(url_or_path)?;
    parsed
        .query_pairs()
        .find_map(|(k, v)| if k == key { Some(v.to_string()) } else { None })
}

fn parse_url_or_path(url_or_path: &str) -> Option<Url> {
    if let Ok(url) = Url::parse(url_or_path) {
        return Some(url);
    }

    let normalized = if url_or_path.starts_with('/') {
        format!("http://localhost{url_or_path}")
    } else {
        format!("http://localhost/{url_or_path}")
    };

    Url::parse(&normalized).ok()
}

fn derive_return_to(current_request_url: &str) -> String {
    let without_fragment = current_request_url
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(current_request_url);

    let candidate = if let Ok(url) = Url::parse(without_fragment) {
        let mut value = url.path().to_string();
        if let Some(query) = url.query() {
            value.push('?');
            value.push_str(query);
        }
        value
    } else {
        without_fragment.to_string()
    };

    validate_return_to(&candidate)
}

fn validate_return_to(input: &str) -> String {
    let no_fragment = input
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(input)
        .trim();

    if no_fragment.is_empty() {
        return "/".to_string();
    }

    if !no_fragment.starts_with('/') || no_fragment.starts_with("//") {
        return "/".to_string();
    }

    if no_fragment.contains("://") || no_fragment.len() > MAX_RETURN_TO_LEN {
        return "/".to_string();
    }

    no_fragment.to_string()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

/// An OIDC provider instance that handles authentication against a single
/// OpenID Connect identity provider.
///
/// Created during `vcl_init` by providing the provider's discovery URL,
/// client credentials, and cookie configuration. The provider fetches the
/// discovery document and JWKS at initialization time — if either fails,
/// `vcl_init` fails (fail-closed startup).
///
/// A single Varnish instance can have multiple provider objects for
/// different identity providers (e.g., Google and Keycloak), each with
/// its own cookie name and configuration.
#[cfg(feature = "vmod")]
#[allow(non_camel_case_types)]
pub struct provider {
    inner: Provider,
}

/// OpenID Connect authentication for Varnish Cache.
///
/// This VMOD allows Varnish to act as an OpenID Connect Relying Party,
/// authenticating users against any OIDC-compliant identity provider
/// (Google, Microsoft Entra ID, Keycloak, Auth0, etc.) before serving
/// cached content.
///
/// # How it works
///
/// The VMOD implements the standard OIDC Authorization Code flow:
///
/// 1. An unauthenticated request arrives at a protected path.
/// 2. VCL calls `session_valid()` which returns `FALSE` (no valid cookie).
/// 3. VCL calls `authorization_url()` and redirects the user to the identity provider.
/// 4. The user authenticates with the provider and is redirected back with an authorization code.
/// 5. VCL calls `exchange_code_for_session(code)` which exchanges the code for an ID token,
///    validates it, and returns a `Set-Cookie` header containing the encrypted session.
/// 6. Subsequent requests include the session cookie; `session_valid()` returns `TRUE` and
///    individual claims (email, name, etc.) are available via `claim()`.
///
/// # Session model
///
/// Sessions are **stateless and cookie-based**. The full set of ID token claims is
/// AES-256-GCM encrypted and stored directly in the cookie. No external session store
/// (Redis, memcached, etc.) is needed. Sessions survive Varnish restarts and work across
/// multiple Varnish instances sharing the same `cookie_secret`.
///
/// Session revocation is not supported in v1 — a session is valid until it expires.
///
/// # Security properties
///
/// - **Fail-closed**: all validation failures return empty string or `FALSE`. Partial
///   data is never leaked.
/// - **Issuer validation**: always enabled; the `iss` claim must match the discovery document.
/// - **Nonce binding**: the `nonce` in the ID token must match the nonce stored in the state cookie.
/// - **Cookie protection**: session and state cookies are `HttpOnly`, `SameSite=Lax`, `Path=/`,
///   and `Secure` by default. Contents are encrypted and authenticated with AES-256-GCM.
/// - **JWKS rotation**: unknown key IDs trigger an automatic JWKS refresh with exponential backoff.
///
/// # VCL example
///
/// ```vcl
/// import oidc;
///
/// sub vcl_init {
///     new google = oidc.provider(
///         discovery_url = "https://accounts.google.com/.well-known/openid-configuration",
///         client_id     = "your-client-id.apps.googleusercontent.com",
///         client_secret = "your-client-secret",
///         redirect_uri  = "https://example.com/oidc/callback",
///         cookie_secret = "hex-or-base64-encoded-32-byte-key"
///     );
/// }
///
/// sub vcl_recv {
///     // Handle the OIDC callback
///     if (req.url ~ "^/oidc/callback") {
///         if (!google.callback_state_valid()) {
///             return (synth(403, "Invalid state"));
///         }
///         set req.http.X-Set-Cookie = google.exchange_code_for_session(
///             google.callback_code()
///         );
///         if (req.http.X-Set-Cookie == "") {
///             return (synth(403, "Authentication failed"));
///         }
///         return (synth(302, "Authenticated"));
///     }
///
///     // Protect specific paths
///     if (req.url ~ "^/protected/") {
///         if (!google.session_valid()) {
///             return (synth(302, "Login required"));
///         }
///         set req.http.X-User-Email = google.claim("email");
///     }
/// }
///
/// sub vcl_synth {
///     if (resp.status == 302 && resp.reason == "Login required") {
///         set resp.http.Location = google.authorization_url();
///         return (deliver);
///     }
///     if (resp.status == 302 && resp.reason == "Authenticated") {
///         set resp.http.Set-Cookie = req.http.X-Set-Cookie;
///         set resp.http.Location = google.callback_redirect_target();
///         return (deliver);
///     }
/// }
/// ```
#[cfg(feature = "vmod")]
#[varnish::vmod(docs = "README.md")]
mod oidc {
    use super::{Provider, ProviderConfig, provider};
    use std::time::Duration;
    use varnish::vcl::Ctx;

    impl provider {
        /// Create a new OIDC provider by fetching and validating the discovery document
        /// and JWKS from the identity provider. This is called during `vcl_init`.
        ///
        /// If the discovery document or JWKS cannot be fetched, initialization fails
        /// and Varnish will not start (fail-closed).
        ///
        /// The `cookie_secret` must decode to exactly 32 bytes. It accepts hex,
        /// base64, or base64url encoding. Generate one with:
        /// `openssl rand -hex 32`
        #[expect(clippy::too_many_arguments)]
        pub fn new(
            /// The OIDC discovery endpoint URL, typically ending in
            /// `/.well-known/openid-configuration`.
            discovery_url: &str,
            /// The OAuth 2.0 client ID registered with the identity provider.
            client_id: &str,
            /// The OAuth 2.0 client secret registered with the identity provider.
            client_secret: &str,
            /// The absolute URL the provider will redirect to after authentication.
            /// Must match the redirect URI registered with the provider.
            redirect_uri: &str,
            /// A 32-byte secret used for AES-256-GCM encryption of session and
            /// state cookies. Accepts hex, base64, or base64url encoding.
            cookie_secret: &str,
            /// Name of the session cookie. Defaults to `__oidc`.
            cookie_name: Option<&str>,
            /// Session cookie lifetime. Defaults to 1 hour.
            cookie_ttl: Option<Duration>,
            /// State cookie lifetime (used during the login flow). Defaults to 5 minutes.
            state_cookie_ttl: Option<Duration>,
            /// Whether to set the `Secure` flag on cookies. Defaults to `true`.
            /// Set to `false` only for local development over plain HTTP.
            cookie_secure: Option<bool>,
            /// Space-separated list of OAuth scopes to request. Defaults to `"openid"`.
            /// Common additions: `"openid email profile"`.
            scopes: Option<&str>,
        ) -> Result<Self, String> {
            let config = ProviderConfig {
                discovery_url: discovery_url.to_string(),
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                redirect_uri: redirect_uri.to_string(),
                cookie_secret: cookie_secret.to_string(),
                cookie_name: cookie_name.unwrap_or_default().to_string(),
                state_cookie_name: String::new(),
                cookie_ttl_secs: cookie_ttl.map(|v| v.as_secs()).unwrap_or(0),
                state_cookie_ttl_secs: state_cookie_ttl.map(|v| v.as_secs()).unwrap_or(0),
                cookie_secure: cookie_secure.unwrap_or(true),
                scopes: scopes.unwrap_or_default().to_string(),
            };

            Provider::new(config)
                .map(|inner| Self { inner })
                .map_err(|err| err.to_string())
        }

        /// Returns `TRUE` if the request carries a valid, non-expired session cookie.
        ///
        /// Use this in `vcl_recv` to decide whether a request is authenticated.
        /// Returns `FALSE` if the cookie is missing, expired, tampered with, or
        /// encrypted with a different key.
        pub fn session_valid(&self, ctx: &Ctx) -> bool {
            self.inner
                .session_valid(super::cookie_header_from_ctx(ctx).as_deref())
        }

        /// Returns the value of a named claim from the session cookie.
        ///
        /// String and numeric claims are returned as plain strings. Array and
        /// object claims are returned as compact JSON. Returns an empty string
        /// if the session is invalid or the claim does not exist.
        ///
        /// ```vcl
        /// set req.http.X-User-Email = google.claim("email");
        /// set req.http.X-User-Sub   = google.claim("sub");
        /// ```
        pub fn claim(&self, ctx: &Ctx,
            /// The claim name to look up (e.g., `"email"`, `"sub"`, `"name"`).
            name: &str,
        ) -> String {
            self.inner
                .claim(super::cookie_header_from_ctx(ctx).as_deref(), name)
        }

        /// Returns the full authorization URL to redirect the user to the identity
        /// provider. As a side effect, sets a short-lived state cookie on the response
        /// containing the CSRF state token, nonce, and the return-to path.
        ///
        /// Call this in `vcl_synth` when an unauthenticated user needs to log in,
        /// and use the returned URL as the `Location` header for a 302 redirect.
        ///
        /// Returns an empty string on internal error (e.g., failed to set the
        /// state cookie on the response).
        pub fn authorization_url(&self, ctx: &mut Ctx) -> String {
            let req_url = super::request_url_from_ctx(ctx).unwrap_or_else(|| "/".to_string());
            let start = match self.inner.authorization_url(&req_url) {
                Ok(start) => start,
                Err(_) => return String::new(),
            };

            if !super::set_response_cookie_on_ctx(ctx, &start.state_set_cookie) {
                return String::new();
            }

            start.url
        }

        /// Extracts the `code` query parameter from the current callback request URL.
        ///
        /// Returns an empty string if the parameter is missing.
        pub fn callback_code(&self, ctx: &Ctx) -> String {
            super::request_url_from_ctx(ctx)
                .map(|url| self.inner.callback_code(&url))
                .unwrap_or_default()
        }

        /// Extracts the `state` query parameter from the current callback request URL.
        ///
        /// Returns an empty string if the parameter is missing.
        pub fn callback_state(&self, ctx: &Ctx) -> String {
            super::request_url_from_ctx(ctx)
                .map(|url| self.inner.callback_state(&url))
                .unwrap_or_default()
        }

        /// Validates the OIDC callback by checking that the `state` query parameter
        /// matches the value stored in the encrypted state cookie.
        ///
        /// Returns `FALSE` if the state cookie is missing, expired, tampered with,
        /// or does not match the `state` parameter. This is a CSRF protection check
        /// and should be called before `exchange_code_for_session()`.
        pub fn callback_state_valid(&self, ctx: &Ctx) -> bool {
            let Some(url) = super::request_url_from_ctx(ctx) else {
                return false;
            };
            self.inner
                .callback_state_valid(&url, super::cookie_header_from_ctx(ctx).as_deref())
        }

        /// Exchanges an authorization code for an ID token, validates the token,
        /// and returns a `Set-Cookie` header value containing the encrypted session.
        ///
        /// This method performs the following steps:
        /// 1. Validates the state cookie (CSRF check).
        /// 2. POSTs the authorization code to the provider's token endpoint.
        /// 3. Validates the returned ID token (signature, issuer, audience, expiry, nonce).
        /// 4. Encrypts the ID token claims into a session cookie.
        ///
        /// Returns an empty string on any failure (network error, invalid token,
        /// state mismatch, etc.). The VCL should check for an empty return value
        /// and respond with a 403 or similar error.
        ///
        /// The returned string is a complete `Set-Cookie` header value that should
        /// be set on the response (e.g., `set resp.http.Set-Cookie = ...`).
        pub fn exchange_code_for_session(&self, ctx: &Ctx,
            /// The authorization code from the callback query string.
            /// Typically obtained via `callback_code()`.
            code: &str,
        ) -> String {
            let Some(url) = super::request_url_from_ctx(ctx) else {
                return String::new();
            };
            self.inner.exchange_code_for_session(
                code,
                &url,
                super::cookie_header_from_ctx(ctx).as_deref(),
            )
        }

        /// Returns the original URL path the user was trying to access before
        /// being redirected to log in. This is extracted from the encrypted state
        /// cookie that was set during `authorization_url()`.
        ///
        /// Returns `"/"` if the state is invalid, expired, or the stored path
        /// fails validation (e.g., contains a scheme/host or exceeds 2048 bytes).
        ///
        /// Use this as the `Location` header when redirecting the user after
        /// successful authentication.
        pub fn callback_redirect_target(&self, ctx: &Ctx) -> String {
            let Some(url) = super::request_url_from_ctx(ctx) else {
                return "/".to_string();
            };
            self.inner
                .callback_redirect_target(&url, super::cookie_header_from_ctx(ctx).as_deref())
        }
    }
}

#[cfg(feature = "vmod")]
fn request_url_from_ctx(ctx: &varnish::vcl::Ctx) -> Option<String> {
    [
        ctx.http_req.as_ref(),
        ctx.http_req_top.as_ref(),
        ctx.http_bereq.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find_map(|headers| headers.url().map(str_or_bytes_to_string))
}

#[cfg(feature = "vmod")]
fn cookie_header_from_ctx(ctx: &varnish::vcl::Ctx) -> Option<String> {
    [
        ctx.http_req.as_ref(),
        ctx.http_req_top.as_ref(),
        ctx.http_bereq.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find_map(|headers| headers.header("Cookie").map(str_or_bytes_to_string))
}

#[cfg(feature = "vmod")]
fn set_response_cookie_on_ctx(ctx: &mut varnish::vcl::Ctx, value: &str) -> bool {
    let Some(resp) = ctx.http_resp.as_mut() else {
        return false;
    };
    resp.set_header("Set-Cookie", value).is_ok()
}

#[cfg(feature = "vmod")]
fn str_or_bytes_to_string(input: varnish::vcl::StrOrBytes<'_>) -> String {
    String::from_utf8_lossy(input.as_ref()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use mockito::Matcher;
    use serde_json::json;

    const TEST_SECRET_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const FIXTURE_RSA_PRIVATE_PEM: &str = include_str!("../fixtures/test-keys/rsa-private.pem");
    const FIXTURE_WRONG_RSA_PRIVATE_PEM: &str =
        include_str!("../fixtures/test-keys/wrong-key-private.pem");
    const FIXTURE_JWKS_JSON: &str = include_str!("../fixtures/test-keys/jwks.json");

    fn test_config(discovery_url: String) -> ProviderConfig {
        ProviderConfig {
            discovery_url,
            client_id: "client-123".to_string(),
            client_secret: "secret-xyz".to_string(),
            redirect_uri: "https://example.test/oidc/callback".to_string(),
            cookie_secret: TEST_SECRET_HEX.to_string(),
            cookie_name: "__oidc_test".to_string(),
            state_cookie_name: "__oidc_state_test".to_string(),
            cookie_ttl_secs: 3600,
            state_cookie_ttl_secs: 300,
            cookie_secure: true,
            scopes: "openid email profile".to_string(),
        }
    }

    fn setup_provider_server() -> (mockito::ServerGuard, Provider) {
        let mut server = mockito::Server::new();

        let discovery_path = "/.well-known/openid-configuration";
        let jwks_path = "/jwks";
        let token_path = "/token";

        server
            .mock("GET", discovery_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                "{{\"issuer\":\"{}\",\"authorization_endpoint\":\"{}/authorize\",\"token_endpoint\":\"{}{}\",\"jwks_uri\":\"{}{}\"}}",
                server.url(),
                server.url(),
                server.url(),
                token_path,
                server.url(),
                jwks_path
            ))
            .create();

        server
            .mock("GET", jwks_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header("cache-control", "max-age=120")
            .with_body(
                "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"kid\":\"test-key\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}",
            )
            .create();

        let provider = Provider::new(test_config(format!("{}{}", server.url(), discovery_path)))
            .expect("provider should initialize");

        (server, provider)
    }

    fn setup_provider_server_with_fixture_jwks() -> (mockito::ServerGuard, Provider, String) {
        let mut server = mockito::Server::new();
        let discovery_path = "/.well-known/openid-configuration";
        let jwks_path = "/jwks";
        let token_path = "/token";

        server
            .mock("GET", discovery_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                "{{\"issuer\":\"{}\",\"authorization_endpoint\":\"{}/authorize\",\"token_endpoint\":\"{}{}\",\"jwks_uri\":\"{}{}\"}}",
                server.url(),
                server.url(),
                server.url(),
                token_path,
                server.url(),
                jwks_path
            ))
            .create();

        server
            .mock("GET", jwks_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(FIXTURE_JWKS_JSON)
            .create();

        let provider = Provider::new(test_config(format!("{}{}", server.url(), discovery_path)))
            .expect("provider should initialize");

        (server, provider, token_path.to_string())
    }

    fn cookie_pair_from_set_cookie(set_cookie: &str) -> String {
        set_cookie
            .split(';')
            .next()
            .expect("set-cookie should contain name=value")
            .trim()
            .to_string()
    }

    fn sign_token_with_claims(claims: &Value, private_pem: &str, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("valid rsa private key");
        encode(&header, claims, &key).expect("token should be signed")
    }

    fn exchange_with_signed_token<F>(token_builder: F) -> String
    where
        F: FnOnce(&str, &str) -> String,
    {
        let (mut server, provider, token_path) = setup_provider_server_with_fixture_jwks();
        let start = provider
            .authorization_url("/protected?x=1")
            .expect("auth start should work");
        let state = query_param(&start.url, "state").expect("state must exist");
        let nonce = query_param(&start.url, "nonce").expect("nonce must exist");

        let token = token_builder(&nonce, &server.url());
        let token_body = format!(
            "{{\"id_token\":\"{token}\",\"access_token\":\"abc\",\"token_type\":\"Bearer\"}}"
        );

        let token_mock = server
            .mock("POST", token_path.as_str())
            .match_header(
                "content-type",
                Matcher::Regex("application/x-www-form-urlencoded.*".to_string()),
            )
            .match_body(Matcher::UrlEncoded(
                "grant_type".into(),
                "authorization_code".into(),
            ))
            .match_body(Matcher::UrlEncoded("code".into(), "auth-code".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(token_body)
            .create();

        let callback_url = format!("/oidc/callback?code=auth-code&state={state}");
        let cookie_header = cookie_pair_from_set_cookie(&start.state_set_cookie);
        let result =
            provider.exchange_code_for_session("auth-code", &callback_url, Some(&cookie_header));
        token_mock.assert();
        result
    }

    #[test]
    fn return_to_rules_are_enforced() {
        assert_eq!(derive_return_to("/protected?a=1#frag"), "/protected?a=1");
        assert_eq!(derive_return_to("https://example.test/p?q=1#x"), "/p?q=1");
        assert_eq!(validate_return_to(""), "/");
        assert_eq!(validate_return_to("http://evil.test"), "/");
        assert_eq!(validate_return_to("//evil"), "/");

        let huge = format!("/{}", "a".repeat(MAX_RETURN_TO_LEN + 1));
        assert_eq!(validate_return_to(&huge), "/");
    }

    #[test]
    fn authorization_url_sets_state_cookie_and_callback_state_validates() {
        let (_server, provider) = setup_provider_server();

        let start = provider
            .authorization_url("https://example.test/protected/data?x=1#frag")
            .expect("authorization_url should succeed");

        assert!(start.url.contains("response_type=code"));
        assert!(start.url.contains("client_id=client-123"));
        assert!(
            start
                .url
                .contains("redirect_uri=https%3A%2F%2Fexample.test%2Foidc%2Fcallback")
        );
        assert!(start.url.contains("scope=openid+email+profile"));

        assert!(start.state_set_cookie.contains("HttpOnly"));
        assert!(start.state_set_cookie.contains("SameSite=Lax"));
        assert!(start.state_set_cookie.contains("Path=/"));
        assert!(start.state_set_cookie.contains("Secure"));

        let state = query_param(&start.url, "state").expect("state must exist");
        let callback_url = format!("/oidc/callback?code=abc&state={state}");
        let cookie_header = cookie_pair_from_set_cookie(&start.state_set_cookie);

        assert!(provider.callback_state_valid(&callback_url, Some(&cookie_header)));
        assert_eq!(
            provider.callback_redirect_target(&callback_url, Some(&cookie_header)),
            "/protected/data?x=1"
        );

        assert!(
            !provider
                .callback_state_valid("/oidc/callback?code=abc&state=wrong", Some(&cookie_header))
        );
        assert_eq!(
            provider.callback_redirect_target(
                "/oidc/callback?code=abc&state=wrong",
                Some(&cookie_header)
            ),
            "/"
        );
    }

    #[test]
    fn session_cookie_roundtrip_and_claim_readback() {
        let (_server, provider) = setup_provider_server();

        let claims = serde_json::json!({
            "sub": "123",
            "email": "user@example.test",
            "roles": ["admin", "viewer"],
            "profile": {"name": "User"},
            "iat": now_secs() as i64,
            "exp": (now_secs() + 60) as i64
        });

        let set_cookie = provider
            .create_session_cookie_from_claims(&claims)
            .expect("session cookie should be created");
        let cookie_header = cookie_pair_from_set_cookie(&set_cookie);

        assert!(provider.session_valid(Some(&cookie_header)));
        assert_eq!(
            provider.claim(Some(&cookie_header), "email"),
            "user@example.test"
        );
        assert_eq!(provider.claim(Some(&cookie_header), "sub"), "123");
        assert_eq!(
            provider.claim(Some(&cookie_header), "roles"),
            "[\"admin\",\"viewer\"]"
        );
        assert_eq!(
            provider.claim(Some(&cookie_header), "profile"),
            "{\"name\":\"User\"}"
        );
        assert_eq!(provider.claim(Some(&cookie_header), "missing"), "");

        let expired_claims = serde_json::json!({
            "sub": "123",
            "iat": now_secs() as i64,
            "exp": (now_secs() - 1) as i64
        });
        let expired_cookie = provider
            .create_session_cookie_from_claims(&expired_claims)
            .expect("expired cookie still serializes");
        let expired_header = cookie_pair_from_set_cookie(&expired_cookie);
        assert!(!provider.session_valid(Some(&expired_header)));
    }

    #[test]
    fn exchange_code_failure_returns_empty_string() {
        let mut server = mockito::Server::new();

        let discovery_path = "/.well-known/openid-configuration";
        let jwks_path = "/jwks";
        let token_path = "/token";

        server
            .mock("GET", discovery_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                "{{\"issuer\":\"{}\",\"authorization_endpoint\":\"{}/authorize\",\"token_endpoint\":\"{}{}\",\"jwks_uri\":\"{}{}\"}}",
                server.url(),
                server.url(),
                server.url(),
                token_path,
                server.url(),
                jwks_path
            ))
            .create();

        server
            .mock("GET", jwks_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"kid\":\"test-key\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}",
            )
            .create();

        let token_mock = server
            .mock("POST", token_path)
            .match_header(
                "content-type",
                Matcher::Regex("application/x-www-form-urlencoded.*".to_string()),
            )
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
                Matcher::UrlEncoded("code".into(), "abc123".into()),
                Matcher::UrlEncoded("client_id".into(), "client-123".into()),
                Matcher::UrlEncoded("client_secret".into(), "secret-xyz".into()),
                Matcher::UrlEncoded(
                    "redirect_uri".into(),
                    "https://example.test/oidc/callback".into(),
                ),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{\"access_token\":\"abc\"}")
            .create();

        let provider = Provider::new(test_config(format!("{}{}", server.url(), discovery_path)))
            .expect("provider should initialize");

        let start = provider
            .authorization_url("/protected")
            .expect("auth start should work");

        let state = query_param(&start.url, "state").expect("state must exist");
        let callback_url = format!("/oidc/callback?code=abc123&state={state}");
        let cookie_header = cookie_pair_from_set_cookie(&start.state_set_cookie);

        let result =
            provider.exchange_code_for_session("abc123", &callback_url, Some(&cookie_header));
        assert_eq!(result, "");
        token_mock.assert();
    }

    #[test]
    fn invalid_return_to_falls_back_to_root_without_invalidating_state() {
        let (_server, provider) = setup_provider_server();
        let state = "state-abc";
        let callback_url = "/oidc/callback?code=abc&state=state-abc";

        let state_cookie = StateCookie {
            state: state.to_string(),
            nonce: "nonce-abc".to_string(),
            exp: now_secs() + 60,
            return_to: "https://evil.test/steal".to_string(),
        };

        let value = provider
            .cookie_cipher
            .encrypt_json(&state_cookie)
            .expect("state cookie should encrypt");
        let cookie_header = format!("{}={value}", provider.config.state_cookie_name);

        assert!(provider.callback_state_valid(callback_url, Some(&cookie_header)));
        assert_eq!(
            provider.callback_redirect_target(callback_url, Some(&cookie_header)),
            "/"
        );
    }

    #[test]
    fn provider_init_fails_for_invalid_cookie_secret() {
        let mut server = mockito::Server::new();

        let discovery_path = "/.well-known/openid-configuration";
        let jwks_path = "/jwks";

        server
            .mock("GET", discovery_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                "{{\"issuer\":\"{}\",\"authorization_endpoint\":\"{}/authorize\",\"token_endpoint\":\"{}/token\",\"jwks_uri\":\"{}{}\"}}",
                server.url(),
                server.url(),
                server.url(),
                server.url(),
                jwks_path
            ))
            .create();

        server
            .mock("GET", jwks_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"a\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}")
            .create();

        let mut config = test_config(format!("{}{}", server.url(), discovery_path));
        config.cookie_secret = "invalid".to_string();
        match Provider::new(config) {
            Ok(_) => panic!("provider init should fail on invalid cookie secret"),
            Err(err) => assert!(err.to_string().contains("cookie_secret")),
        }
    }

    #[test]
    fn exchange_code_for_session_accepts_valid_signed_token() {
        let set_cookie = exchange_with_signed_token(|nonce, issuer| {
            let claims = json!({
                "sub": "1234567890",
                "email": "user@example.com",
                "name": "User",
                "iss": issuer,
                "aud": "client-123",
                "iat": now_secs() as i64,
                "exp": (now_secs() + 300) as i64,
                "nonce": nonce
            });
            sign_token_with_claims(&claims, FIXTURE_RSA_PRIVATE_PEM, "test-key")
        });

        assert_ne!(set_cookie, "");
        let cookie_header = cookie_pair_from_set_cookie(&set_cookie);

        let (_server, provider) = setup_provider_server();
        assert!(provider.session_valid(Some(&cookie_header)));
        assert_eq!(
            provider.claim(Some(&cookie_header), "email"),
            "user@example.com"
        );
    }

    #[test]
    fn exchange_code_for_session_rejects_invalid_id_token_variants() {
        let expired = exchange_with_signed_token(|nonce, issuer| {
            let claims = json!({
                "sub": "1234567890",
                "email": "user@example.com",
                "iss": issuer,
                "aud": "client-123",
                "iat": now_secs() as i64,
                "exp": (now_secs() - 3600) as i64,
                "nonce": nonce
            });
            sign_token_with_claims(&claims, FIXTURE_RSA_PRIVATE_PEM, "test-key")
        });
        assert_eq!(expired, "");

        let wrong_aud = exchange_with_signed_token(|nonce, issuer| {
            let claims = json!({
                "sub": "1234567890",
                "email": "user@example.com",
                "iss": issuer,
                "aud": "wrong-client",
                "iat": now_secs() as i64,
                "exp": (now_secs() + 300) as i64,
                "nonce": nonce
            });
            sign_token_with_claims(&claims, FIXTURE_RSA_PRIVATE_PEM, "test-key")
        });
        assert_eq!(wrong_aud, "");

        let wrong_iss = exchange_with_signed_token(|nonce, _issuer| {
            let claims = json!({
                "sub": "1234567890",
                "email": "user@example.com",
                "iss": "http://wrong-issuer",
                "aud": "client-123",
                "iat": now_secs() as i64,
                "exp": (now_secs() + 300) as i64,
                "nonce": nonce
            });
            sign_token_with_claims(&claims, FIXTURE_RSA_PRIVATE_PEM, "test-key")
        });
        assert_eq!(wrong_iss, "");

        let wrong_signature = exchange_with_signed_token(|nonce, issuer| {
            let claims = json!({
                "sub": "1234567890",
                "email": "user@example.com",
                "iss": issuer,
                "aud": "client-123",
                "iat": now_secs() as i64,
                "exp": (now_secs() + 300) as i64,
                "nonce": nonce
            });
            sign_token_with_claims(&claims, FIXTURE_WRONG_RSA_PRIVATE_PEM, "test-key")
        });
        assert_eq!(wrong_signature, "");

        let missing_claims = exchange_with_signed_token(|nonce, _issuer| {
            let claims = json!({
                "email": "user@example.com",
                "iat": now_secs() as i64,
                "exp": (now_secs() + 300) as i64,
                "nonce": nonce
            });
            sign_token_with_claims(&claims, FIXTURE_RSA_PRIVATE_PEM, "test-key")
        });
        assert_eq!(missing_claims, "");
    }
}
