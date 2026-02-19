use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SESSION_COOKIE_PREFIX: &str = "v1.";
const TEST_COOKIE_SECRET_HEX: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_env(env::args().skip(1))?;
    generate_fixtures(&args.output, &args.issuer, &args.client_id)
}

#[derive(Debug)]
struct Args {
    output: PathBuf,
    issuer: String,
    client_id: String,
}

impl Args {
    fn from_env(mut args: impl Iterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let mut output = PathBuf::from("fixtures");
        let mut issuer = String::from("http://localhost");
        let mut client_id = String::from("client-123");

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--output" => {
                    output = PathBuf::from(args.next().ok_or("--output requires a path argument")?)
                }
                "--issuer" => {
                    issuer = args.next().ok_or("--issuer requires a value")?;
                }
                "--client-id" => {
                    client_id = args.next().ok_or("--client-id requires a value")?;
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => {
                    return Err(format!("unexpected argument: {arg}\nUse --help for usage.").into());
                }
            }
        }

        Ok(Self {
            output,
            issuer,
            client_id,
        })
    }
}

fn print_help() {
    eprintln!(
        "Usage: cargo run -p gen-test-fixtures -- [--output DIR] [--issuer URL] [--client-id ID]"
    );
}

fn generate_fixtures(
    output_dir: &Path,
    issuer: &str,
    client_id: &str,
) -> Result<(), Box<dyn Error>> {
    let key_dir = output_dir.join("test-keys");
    let token_dir = output_dir.join("tokens");
    let cookie_dir = output_dir.join("cookies");
    fs::create_dir_all(&key_dir)?;
    fs::create_dir_all(&token_dir)?;
    fs::create_dir_all(&cookie_dir)?;

    let mut rng = OsRng;
    let good_private = RsaPrivateKey::new(&mut rng, 2048)?;
    let good_public = RsaPublicKey::from(&good_private);

    let wrong_private = RsaPrivateKey::new(&mut rng, 2048)?;

    let good_private_pem = good_private.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let good_public_pem = good_public.to_public_key_pem(LineEnding::LF)?;
    let wrong_private_pem = wrong_private.to_pkcs8_pem(LineEnding::LF)?.to_string();

    fs::write(key_dir.join("rsa-private.pem"), &good_private_pem)?;
    fs::write(key_dir.join("rsa-public.pem"), &good_public_pem)?;
    fs::write(key_dir.join("wrong-key-private.pem"), &wrong_private_pem)?;

    let n = URL_SAFE_NO_PAD.encode(good_public.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(good_public.e().to_bytes_be());
    let jwks = json!({
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key",
                "use": "sig",
                "alg": "RS256",
                "n": n,
                "e": e,
            }
        ]
    });
    fs::write(key_dir.join("jwks.json"), serde_json::to_vec_pretty(&jwks)?)?;

    let now = now_secs();
    let valid_exp = 4_102_444_800_i64; // 2100-01-01
    let expired_exp = 946_684_800_i64; // 2000-01-01

    let valid_claims = json!({
        "sub": "1234567890",
        "email": "user@example.com",
        "name": "Test User",
        "iss": issuer,
        "aud": client_id,
        "iat": now,
        "exp": valid_exp,
        "nonce": "nonce-123"
    });

    let expired_claims = json!({
        "sub": "1234567890",
        "email": "user@example.com",
        "name": "Test User",
        "iss": issuer,
        "aud": client_id,
        "iat": now,
        "exp": expired_exp,
        "nonce": "nonce-123"
    });

    let wrong_aud_claims = json!({
        "sub": "1234567890",
        "email": "user@example.com",
        "name": "Test User",
        "iss": issuer,
        "aud": "wrong-client-id",
        "iat": now,
        "exp": valid_exp,
        "nonce": "nonce-123"
    });

    let wrong_iss_claims = json!({
        "sub": "1234567890",
        "email": "user@example.com",
        "name": "Test User",
        "iss": "http://wrong-issuer",
        "aud": client_id,
        "iat": now,
        "exp": valid_exp,
        "nonce": "nonce-123"
    });

    let missing_claims = json!({
        "email": "user@example.com",
        "iat": now,
        "exp": valid_exp,
        "nonce": "nonce-123"
    });

    write_token(
        token_dir.join("valid.jwt"),
        &valid_claims,
        &good_private_pem,
        "test-key",
    )?;
    write_token(
        token_dir.join("expired.jwt"),
        &expired_claims,
        &good_private_pem,
        "test-key",
    )?;
    write_token(
        token_dir.join("wrong-audience.jwt"),
        &wrong_aud_claims,
        &good_private_pem,
        "test-key",
    )?;
    write_token(
        token_dir.join("wrong-issuer.jwt"),
        &wrong_iss_claims,
        &good_private_pem,
        "test-key",
    )?;
    write_token(
        token_dir.join("wrong-signature.jwt"),
        &valid_claims,
        &wrong_private_pem,
        "test-key",
    )?;
    write_token(
        token_dir.join("missing-claims.jwt"),
        &missing_claims,
        &good_private_pem,
        "test-key",
    )?;
    write_cookie_fixtures(&cookie_dir, valid_exp, expired_exp)?;

    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64
}

fn write_token(
    path: PathBuf,
    claims: &serde_json::Value,
    private_key_pem: &str,
    kid: &str,
) -> Result<(), Box<dyn Error>> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
    let token = encode(&header, claims, &key)?;
    fs::write(path, token)?;
    Ok(())
}

fn write_cookie_fixtures(
    cookie_dir: &Path,
    valid_exp: i64,
    expired_exp: i64,
) -> Result<(), Box<dyn Error>> {
    let key_bytes = hex::decode(TEST_COOKIE_SECRET_HEX)?;
    let key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "cookie secret must be 32 bytes")?;

    let valid_session = json!({
        "sub": "1234567890",
        "email": "user@example.com",
        "name": "Test User",
        "iss": "http://localhost",
        "aud": "client-123",
        "iat": now_secs(),
        "exp": valid_exp,
        "nonce": "nonce-123",
    });
    let expired_session = json!({
        "sub": "1234567890",
        "email": "user@example.com",
        "name": "Test User",
        "iss": "http://localhost",
        "aud": "client-123",
        "iat": now_secs(),
        "exp": expired_exp,
        "nonce": "nonce-123",
    });
    let state_valid = json!({
        "state": "state-valid",
        "nonce": "nonce-123",
        "exp": valid_exp,
        "return_to": "/protected/resource?x=1",
    });
    let state_invalid_return_to = json!({
        "state": "state-invalid-target",
        "nonce": "nonce-123",
        "exp": valid_exp,
        "return_to": "https://evil.test/steal",
    });
    let state_expired = json!({
        "state": "state-expired",
        "nonce": "nonce-123",
        "exp": valid_exp,
        "return_to": "/protected/resource?x=1",
    });
    let state_wrong_audience = json!({
        "state": "state-wrong-audience",
        "nonce": "nonce-123",
        "exp": valid_exp,
        "return_to": "/protected/resource?x=1",
    });
    let state_wrong_issuer = json!({
        "state": "state-wrong-issuer",
        "nonce": "nonce-123",
        "exp": valid_exp,
        "return_to": "/protected/resource?x=1",
    });
    let state_wrong_signature = json!({
        "state": "state-wrong-signature",
        "nonce": "nonce-123",
        "exp": valid_exp,
        "return_to": "/protected/resource?x=1",
    });
    let state_missing_claims = json!({
        "state": "state-missing-claims",
        "nonce": "nonce-123",
        "exp": valid_exp,
        "return_to": "/protected/resource?x=1",
    });

    fs::write(
        cookie_dir.join("valid-session.cookie"),
        encrypt_cookie_json(
            &key,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            &valid_session,
        )?,
    )?;
    fs::write(
        cookie_dir.join("expired-session.cookie"),
        encrypt_cookie_json(
            &key,
            &[11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
            &expired_session,
        )?,
    )?;
    fs::write(
        cookie_dir.join("state-valid.cookie"),
        encrypt_cookie_json(&key, &[1, 3, 5, 7, 9, 11, 0, 2, 4, 6, 8, 10], &state_valid)?,
    )?;
    fs::write(
        cookie_dir.join("state-invalid-return-to.cookie"),
        encrypt_cookie_json(
            &key,
            &[10, 8, 6, 4, 2, 0, 11, 9, 7, 5, 3, 1],
            &state_invalid_return_to,
        )?,
    )?;
    fs::write(
        cookie_dir.join("state-expired.cookie"),
        encrypt_cookie_json(
            &key,
            &[2, 4, 6, 8, 10, 0, 1, 3, 5, 7, 9, 11],
            &state_expired,
        )?,
    )?;
    fs::write(
        cookie_dir.join("state-wrong-audience.cookie"),
        encrypt_cookie_json(
            &key,
            &[3, 6, 9, 0, 2, 5, 8, 11, 1, 4, 7, 10],
            &state_wrong_audience,
        )?,
    )?;
    fs::write(
        cookie_dir.join("state-wrong-issuer.cookie"),
        encrypt_cookie_json(
            &key,
            &[4, 8, 1, 5, 9, 2, 6, 10, 3, 7, 11, 0],
            &state_wrong_issuer,
        )?,
    )?;
    fs::write(
        cookie_dir.join("state-wrong-signature.cookie"),
        encrypt_cookie_json(
            &key,
            &[5, 10, 4, 9, 3, 8, 2, 7, 1, 6, 0, 11],
            &state_wrong_signature,
        )?,
    )?;
    fs::write(
        cookie_dir.join("state-missing-claims.cookie"),
        encrypt_cookie_json(
            &key,
            &[6, 0, 7, 1, 8, 2, 9, 3, 10, 4, 11, 5],
            &state_missing_claims,
        )?,
    )?;

    Ok(())
}

fn encrypt_cookie_json(
    key: &[u8; 32],
    nonce: &[u8; 12],
    payload: &serde_json::Value,
) -> Result<String, Box<dyn Error>> {
    let cipher = Aes256Gcm::new(key.into());
    let plaintext = serde_json::to_vec(payload)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext.as_ref())
        .map_err(|_| "aes-gcm encryption failed")?;
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(format!(
        "{SESSION_COOKIE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(out)
    ))
}
