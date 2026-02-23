use crate::{OidcBackendResponse, Provider};
use std::sync::Arc;

/// The Varnish backend implementation that handles OIDC requests directly.
struct OidcBackend {
    inner: Arc<Provider>,
}

impl varnish::vcl::VclBackend<()> for OidcBackend {
    fn get_response(
        &self,
        ctx: &mut varnish::vcl::Ctx,
    ) -> Result<Option<()>, varnish::vcl::VclError> {
        let url = ctx
            .http_bereq
            .as_ref()
            .and_then(|h| h.url())
            .and_then(sob_to_string)
            .unwrap_or_default();

        let cookie = ctx
            .http_bereq
            .as_ref()
            .and_then(|h| h.header("Cookie"))
            .and_then(sob_to_string);

        let response = self.inner.handle_backend_request(&url, cookie.as_deref());

        let beresp = ctx
            .http_beresp
            .as_mut()
            .ok_or_else(|| varnish::vcl::VclError::new("no beresp available".to_string()))?;

        match response {
            OidcBackendResponse::LoginRedirect {
                location,
                state_set_cookie,
            } => {
                beresp.set_status(302);
                beresp.set_header("Location", &location)?;
                beresp.set_header("Set-Cookie", &state_set_cookie)?;
                beresp.set_header("Cache-Control", "no-store")?;
            }
            OidcBackendResponse::CallbackSuccess {
                location,
                session_set_cookie,
            } => {
                beresp.set_status(302);
                beresp.set_header("Location", &location)?;
                beresp.set_header("Set-Cookie", &session_set_cookie)?;
                beresp.set_header("Cache-Control", "no-store")?;
            }
            OidcBackendResponse::Error { status } => {
                beresp.set_status(status);
                beresp.set_header("Cache-Control", "no-store")?;
            }
        }

        Ok(Some(()))
    }
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
#[allow(non_camel_case_types)]
pub struct provider {
    inner: Arc<Provider>,
    backend: varnish::vcl::Backend<OidcBackend, ()>,
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
/// The VMOD implements the standard OIDC Authorization Code flow using a
/// built-in Varnish backend that generates redirect and error responses
/// directly — no `vcl_synth` state machine is needed:
///
/// 1. An unauthenticated request arrives at a protected path.
/// 2. VCL calls `session_valid()` which returns `FALSE` (no valid cookie).
/// 3. VCL sets `req.backend_hint = provider.backend()` and returns `pass`.
/// 4. The built-in backend generates a 302 redirect to the identity provider,
///    setting the state cookie automatically.
/// 5. The user authenticates and is redirected back to the callback path.
/// 6. VCL routes the callback to the same backend, which exchanges the code
///    for an ID token, validates it, and returns a 302 redirect with the
///    encrypted session cookie.
/// 7. Subsequent requests include the session cookie; `session_valid()` returns
///    `TRUE` and individual claims are available via `claim()`.
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
/// import std;
///
/// backend default {
///     .host = "127.0.0.1";
///     .port = "8080";
/// }
///
/// sub vcl_init {
///     new google = oidc.provider(
///         discovery_url = "https://accounts.google.com/.well-known/openid-configuration",
///         client_id     = std.getenv("OIDC_CLIENT_ID"),
///         client_secret = std.getenv("OIDC_CLIENT_SECRET"),
///         redirect_uri  = "https://www.example.com/oidc/callback",
///         cookie_secret = std.getenv("OIDC_JWT_SECRET"),
///         scopes        = "openid email profile"
///     );
/// }
///
/// sub vcl_recv {
///     if (req.url ~ "^/oidc/callback") {
///         set req.backend_hint = google.backend();
///         return (pass);
///     }
///     if (req.url ~ "^/app/") {
///         if (!google.session_valid()) {
///             set req.backend_hint = google.backend();
///             return (pass);
///         }
///         set req.http.X-User-Email = google.claim("email");
///     }
/// }
/// // No vcl_synth needed!
/// ```
#[varnish::vmod(docs = "README.md")]
mod oidc {
    use super::{OidcBackend, provider};
    use crate::{Provider, ProviderConfig};
    use std::sync::Arc;
    use std::time::Duration;
    use varnish::ffi::VCL_BACKEND;
    use varnish::vcl::{Backend, Ctx};

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
            ctx: &mut Ctx,
            #[vcl_name] vcl_name: &str,
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

            let inner = Arc::new(Provider::new(config).map_err(|e| e.to_string())?);
            let oidc_backend = OidcBackend {
                inner: inner.clone(),
            };
            let backend = Backend::new(ctx, "oidc", vcl_name, oidc_backend, false)
                .map_err(|e| e.to_string())?;

            Ok(Self { inner, backend })
        }

        /// Returns the built-in OIDC backend that generates redirect and error
        /// responses directly. Use this as `req.backend_hint` in `vcl_recv` for:
        ///
        /// - **Callback requests** (`/oidc/callback`): validates the state cookie,
        ///   exchanges the authorization code for a session, and redirects the user
        ///   back to the original URL with a `Set-Cookie` header.
        /// - **Login redirects**: generates a 302 redirect to the identity provider's
        ///   authorization endpoint with the appropriate state cookie.
        ///
        /// The backend determines whether a request is a callback or a login redirect
        /// by comparing the request path against the configured `redirect_uri` path.
        pub unsafe fn backend(&self) -> VCL_BACKEND {
            self.backend.vcl_ptr()
        }

        /// Returns `TRUE` if the request carries a valid, non-expired session cookie.
        ///
        /// Use this in `vcl_recv` to decide whether a request is authenticated.
        /// Returns `FALSE` if the cookie is missing, expired, tampered with, or
        /// encrypted with a different key.
        pub fn session_valid(&self, ctx: &Ctx) -> bool {
            super::with_cookie_header(ctx, |cookie| self.inner.session_valid(cookie))
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
        pub fn claim(
            &self,
            ctx: &Ctx,
            /// The claim name to look up (e.g., `"email"`, `"sub"`, `"name"`).
            name: &str,
        ) -> String {
            super::with_cookie_header(ctx, |cookie| self.inner.claim(cookie, name))
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
            let start = super::with_request_url(ctx, |url| {
                self.inner.authorization_url(url.unwrap_or("/"))
            });
            let start = match start {
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
            super::with_request_url(ctx, |url| {
                url.map(|u| self.inner.callback_code(u)).unwrap_or_default()
            })
        }

        /// Extracts the `state` query parameter from the current callback request URL.
        ///
        /// Returns an empty string if the parameter is missing.
        pub fn callback_state(&self, ctx: &Ctx) -> String {
            super::with_request_url(ctx, |url| {
                url.map(|u| self.inner.callback_state(u)).unwrap_or_default()
            })
        }

        /// Validates the OIDC callback by checking that the `state` query parameter
        /// matches the value stored in the encrypted state cookie.
        ///
        /// Returns `FALSE` if the state cookie is missing, expired, tampered with,
        /// or does not match the `state` parameter. This is a CSRF protection check
        /// and should be called before `exchange_code_for_session()`.
        pub fn callback_state_valid(&self, ctx: &Ctx) -> bool {
            super::with_request_url(ctx, |url| {
                let Some(url) = url else { return false };
                super::with_cookie_header(ctx, |cookie| {
                    self.inner.callback_state_valid(url, cookie)
                })
            })
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
        pub fn exchange_code_for_session(
            &self,
            ctx: &Ctx,
            /// The authorization code from the callback query string.
            /// Typically obtained via `callback_code()`.
            code: &str,
        ) -> String {
            super::with_request_url(ctx, |url| {
                let Some(url) = url else {
                    return String::new();
                };
                super::with_cookie_header(ctx, |cookie| {
                    self.inner.exchange_code_for_session(code, url, cookie)
                })
            })
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
            super::with_request_url(ctx, |url| {
                let Some(url) = url else {
                    return "/".to_string();
                };
                super::with_cookie_header(ctx, |cookie| {
                    self.inner.callback_redirect_target(url, cookie)
                })
            })
        }
    }
}

fn sob_to_string(sob: varnish::vcl::StrOrBytes<'_>) -> Option<String> {
    match sob {
        varnish::vcl::StrOrBytes::Utf8(s) => Some(s.to_string()),
        varnish::vcl::StrOrBytes::Bytes(b) => std::str::from_utf8(b).ok().map(|s| s.to_string()),
    }
}

fn with_request_url<F, R>(ctx: &varnish::vcl::Ctx, f: F) -> R
where
    F: FnOnce(Option<&str>) -> R,
{
    let sob = [
        ctx.http_req.as_ref(),
        ctx.http_req_top.as_ref(),
        ctx.http_bereq.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find_map(|headers| headers.url());

    match sob {
        None => f(None),
        Some(varnish::vcl::StrOrBytes::Utf8(s)) => f(Some(s)),
        Some(varnish::vcl::StrOrBytes::Bytes(b)) => match std::str::from_utf8(b) {
            Ok(s) => f(Some(s)),
            Err(_) => f(None),
        },
    }
}

fn with_cookie_header<F, R>(ctx: &varnish::vcl::Ctx, f: F) -> R
where
    F: FnOnce(Option<&str>) -> R,
{
    let sob = [
        ctx.http_req.as_ref(),
        ctx.http_req_top.as_ref(),
        ctx.http_bereq.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find_map(|headers| headers.header("Cookie"));

    match sob {
        None => f(None),
        Some(varnish::vcl::StrOrBytes::Utf8(s)) => f(Some(s)),
        Some(varnish::vcl::StrOrBytes::Bytes(b)) => match std::str::from_utf8(b) {
            Ok(s) => f(Some(s)),
            Err(_) => f(None),
        },
    }
}

fn set_response_cookie_on_ctx(ctx: &mut varnish::vcl::Ctx, value: &str) -> bool {
    let Some(resp) = ctx.http_resp.as_mut() else {
        return false;
    };
    resp.set_header("Set-Cookie", value).is_ok()
}
