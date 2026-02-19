# vmod-oidc v1 specification

Normative rules and design decisions not covered by README.md (user-facing API docs) or CLAUDE.md (developer workflow). For the VMOD interface, VCL examples, and method documentation, see README.md.

## Implementation rules (v1, normative)

- The embedded HTTP client MUST be synchronous (`reqwest::blocking::Client`). The VMOD MUST NOT require an async runtime (Tokio/async-std) in Varnish worker threads.
- ID token validation: `aud` MUST include `client_id`, `exp` MUST be in the future, `iat` MUST be present.
- `nonce` in ID token MUST match the nonce persisted with the corresponding `state`.
- All auth validation failures MUST fail closed (`session_valid()` returns `FALSE`; `exchange_code_for_session()` returns empty string).
- `return_to` MUST start with `/`, MUST NOT start with `//`, and MUST NOT contain scheme/host.
- `return_to` MAY include query string; URL fragments are ignored.
- Callback redirect resolution is one-time use for the auth transaction; invalid/expired state or invalid `return_to` resolves to `/`.

## Token exchange contract

- `exchange_code_for_session(code)` performs `POST token_endpoint` internally.
- Request `Content-Type` is `application/x-www-form-urlencoded` with `client_secret_post`.
- Successful response MUST contain `id_token`; otherwise validation fails.
- Non-2xx token response is treated as authentication failure.
- The call is synchronous and may block the current Varnish worker thread until timeout or response.

## HTTP and JWKS handling

- One shared `reqwest::blocking::Client` per provider instance, created in `vcl_init`.
- Discovery, JWKS, and token exchange HTTP calls use conservative defaults: connect timeout 2s, total timeout 5s.
- HTTP connection pooling SHOULD be enabled on the shared client.
- Respect `Cache-Control` / `max-age` headers from the JWKS endpoint.
- Re-fetch JWKS when encountering an unknown `kid` in an ID token header (key rotation).
- If JWKS refresh fails during request handling, the current request fails authentication (fail-closed), and old cached keys remain until cache expiry.
- JWKS cache refresh SHOULD use exponential backoff after failures to avoid thundering-herd retries.
- Support RS256 (required by OIDC spec). ES256 as a stretch goal.

## State cookie internals

- Contains `{state, nonce, exp, return_to}` encrypted with the same AES-GCM scheme and `v1.` version prefix as the session cookie.
- `callback_state_valid()` checks decryption success, expiry, and exact state match.
- `callback_redirect_target()` returns validated `return_to` from state data, or `/` fallback.
- Replay within TTL is primarily mitigated by OAuth authorization code one-time use at the provider.
- No separate HMAC is used; authenticity/integrity is provided by the GCM tag.

## VTC test plan

Use `varnishtest` with mock OIDC provider backends. Each VTC should only define the server interactions it exercises.

### test-01-redirect-unauthenticated.vtc

Unauthenticated request to a protected path returns 302 to the authorization endpoint. Verify: Location contains `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `nonce`. State cookie is set.

### test-02-valid-session.vtc

Request with valid session cookie passes through to backend. Verify: 200 response, claims headers set on backend request, no redirect.

### test-03-expired-session.vtc

Expired session cookie triggers 302 redirect to authorization endpoint.

### test-04-invalid-cookie.vtc

Tampered/malformed session cookies trigger 302 redirect. Test: corrupted, truncated, wrong-key encrypted. No crash or panic.

### test-05-callback-valid.vtc

Mock token endpoint returns valid ID token. Verify: state matches, token exchange POST correct, session cookie set, 302 redirect to original path+query. Missing/invalid target falls back to `/`.

### test-06-callback-invalid-state.vtc

Mismatched or missing state parameter. Verify: 403, no session cookie, no token exchange.

### test-07-callback-invalid-token.vtc

Invalid ID tokens from token endpoint. Each should produce 403: expired, wrong audience, wrong issuer, invalid signature, missing required claims.

### test-08-claims.vtc

Claims accessible in VCL: `claim("email")` returns email, `claim("sub")` returns subject, `claim("nonexistent")` returns empty string.

### test-09-public-path.vtc

Non-protected paths pass through without authentication or redirect.

### test-10-multiple-providers.vtc

Two providers with separate cookie names. Each redirects to its own authorization endpoint. Session cookies don't interfere.

## Out of scope for v1

- Token refresh (access token renewal via refresh tokens)
- Session revocation / server-side session store
- UserInfo endpoint calls
- PKCE (Proof Key for Code Exchange)
- Logout (RP-initiated or back-channel)
- Multiple redirect URIs
