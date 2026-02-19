//! Integration tests that run against a real Keycloak instance in Docker.
//!
//! These tests are marked `#[ignore]` so `cargo test` skips them.
//! Run via: `cargo test --test keycloak_integration -- --ignored --test-threads=1`
//! Or use: `./integration/run.sh`

use std::time::Duration;
use vmod_oidc::{Provider, ProviderConfig};

const KEYCLOAK_URL: &str = "http://localhost:18080";
const REALM: &str = "test-realm";
const CLIENT_ID: &str = "test-client";
const CLIENT_SECRET: &str = "test-client-secret";
const REDIRECT_URI: &str = "http://localhost:19090/oidc/callback";
const COOKIE_SECRET: &str = "hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const USERNAME: &str = "testuser";
const PASSWORD: &str = "testpassword";

fn discovery_url() -> String {
    format!("{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration")
}

fn make_config() -> ProviderConfig {
    ProviderConfig {
        discovery_url: discovery_url(),
        client_id: CLIENT_ID.to_string(),
        client_secret: CLIENT_SECRET.to_string(),
        redirect_uri: REDIRECT_URI.to_string(),
        cookie_secret: COOKIE_SECRET.to_string(),
        cookie_name: String::new(),
        state_cookie_name: String::new(),
        cookie_ttl_secs: 3600,
        state_cookie_ttl_secs: 300,
        cookie_secure: false,
        scopes: "openid email profile".to_string(),
    }
}

/// Build an HTTP client that simulates a browser: stores cookies and follows
/// redirects except when the target is our callback URI (localhost:19090).
fn build_browser_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.url().host_str() == Some("localhost")
                && attempt.url().port() == Some(19090)
            {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .timeout(Duration::from_secs(15))
        .build()
        .expect("failed to build browser client")
}

/// Parse the login form action URL from Keycloak's HTML login page.
/// Looks for `<form id="kc-form-login" ... action="URL">`.
fn extract_login_form_action(html: &str) -> String {
    let form_marker = "id=\"kc-form-login\"";
    let form_pos = html
        .find(form_marker)
        .expect("could not find kc-form-login in Keycloak HTML");

    let tag_start = html[..form_pos]
        .rfind('<')
        .expect("could not find opening < for form tag");
    let tag_end = html[form_pos..]
        .find('>')
        .expect("could not find closing > for form tag")
        + form_pos;
    let tag = &html[tag_start..=tag_end];

    let action_prefix = "action=\"";
    let action_start = tag
        .find(action_prefix)
        .expect("could not find action attribute in form tag")
        + action_prefix.len();
    let action_end = tag[action_start..]
        .find('"')
        .expect("could not find closing quote for action attribute")
        + action_start;

    tag[action_start..action_end].replace("&amp;", "&")
}

/// Extract the `name=value` pair from a `Set-Cookie` header value.
fn cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .expect("Set-Cookie should contain name=value")
        .trim()
        .to_string()
}

/// Simulate the full OIDC Authorization Code flow against Keycloak.
/// Returns the session cookie header (e.g., `__oidc=v1.ENCRYPTED`).
fn perform_login(provider: &Provider) -> String {
    let browser = build_browser_client();

    // Step 1: Get authorization URL and state cookie from the library
    let auth_start = provider
        .authorization_url("/protected/page")
        .expect("authorization_url should succeed");

    // Step 2: GET the Keycloak authorization endpoint (renders login form)
    let login_page = browser
        .get(&auth_start.url)
        .send()
        .expect("GET auth URL should succeed");
    assert!(
        login_page.status().is_success(),
        "Keycloak should return login page, got {}",
        login_page.status()
    );
    let html = login_page.text().expect("login page should have a text body");

    // Step 3: Parse the login form action and POST credentials
    let form_action = extract_login_form_action(&html);
    let response = browser
        .post(&form_action)
        .form(&[("username", USERNAME), ("password", PASSWORD)])
        .send()
        .expect("POST credentials should succeed");

    // Step 4: Our redirect policy stopped the redirect to localhost:19090.
    // The response is the 302 from Keycloak with a Location header pointing
    // to our callback URI including ?code=...&state=...
    assert!(
        response.status().is_redirection(),
        "expected redirect to callback URI, got status {}",
        response.status()
    );
    let callback_url = response
        .headers()
        .get("location")
        .expect("302 response should have Location header")
        .to_str()
        .expect("Location header should be valid UTF-8")
        .to_string();
    assert!(
        callback_url.starts_with(REDIRECT_URI),
        "callback URL should start with {REDIRECT_URI}, got: {callback_url}"
    );

    // Step 5: Extract authorization code from the callback URL
    let parsed = reqwest::Url::parse(&callback_url).expect("callback URL should be a valid URL");
    let code = parsed
        .query_pairs()
        .find(|(k, _)| k == "code")
        .expect("callback URL should have a code parameter")
        .1
        .to_string();

    // Step 6: Exchange the code for a session cookie via the library
    let state_cookie = cookie_pair(&auth_start.state_set_cookie);
    let set_cookie =
        provider.exchange_code_for_session(&code, &callback_url, Some(&state_cookie));
    assert!(
        !set_cookie.is_empty(),
        "exchange_code_for_session should return a non-empty Set-Cookie"
    );

    cookie_pair(&set_cookie)
}

#[test]
#[ignore]
fn test_provider_init() {
    let provider = Provider::new(make_config());
    assert!(
        provider.is_ok(),
        "Provider::new should succeed against Keycloak: {:?}",
        provider.err()
    );
}

#[test]
#[ignore]
fn test_full_login_flow() {
    let provider = Provider::new(make_config()).expect("provider should init");
    let session_cookie = perform_login(&provider);

    assert!(
        provider.session_valid(Some(&session_cookie)),
        "session should be valid after login"
    );
}

#[test]
#[ignore]
fn test_claim_extraction() {
    let provider = Provider::new(make_config()).expect("provider should init");
    let session_cookie = perform_login(&provider);

    let email = provider.claim(Some(&session_cookie), "email");
    assert_eq!(email, "testuser@example.com", "email claim mismatch");

    let preferred_username = provider.claim(Some(&session_cookie), "preferred_username");
    assert_eq!(
        preferred_username, "testuser",
        "preferred_username claim mismatch"
    );

    let sub = provider.claim(Some(&session_cookie), "sub");
    assert!(!sub.is_empty(), "sub claim should not be empty");

    let email_verified = provider.claim(Some(&session_cookie), "email_verified");
    assert_eq!(email_verified, "true", "email_verified claim mismatch");
}

#[test]
#[ignore]
fn test_session_invalid_without_login() {
    let provider = Provider::new(make_config()).expect("provider should init");

    assert!(
        !provider.session_valid(None),
        "no cookie should mean invalid session"
    );
    assert!(
        !provider.session_valid(Some("")),
        "empty cookie should mean invalid session"
    );
    assert!(
        !provider.session_valid(Some("__oidc=garbage")),
        "garbage cookie should mean invalid session"
    );
    assert!(
        !provider.session_valid(Some("__oidc=v1.notvalidbase64!!")),
        "malformed v1 cookie should mean invalid session"
    );
}

#[test]
#[ignore]
fn test_cross_provider_cookie_isolation() {
    let provider_a = Provider::new(make_config()).expect("provider A should init");

    let mut config_b = make_config();
    config_b.cookie_secret =
        "hex:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string();
    let provider_b = Provider::new(config_b).expect("provider B should init");

    let session_cookie = perform_login(&provider_a);

    assert!(
        provider_a.session_valid(Some(&session_cookie)),
        "provider A should accept its own session"
    );
    assert!(
        !provider_b.session_valid(Some(&session_cookie)),
        "provider B should reject provider A's session (different cookie_secret)"
    );
}
