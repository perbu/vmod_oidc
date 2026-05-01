# vmod-oidc

OpenID Connect authentication for Varnish Cache.

vmod-oidc allows Varnish to act as an OpenID Connect Relying Party,
authenticating users against any OIDC-compliant identity provider
(Google, Microsoft Entra ID, Keycloak, Auth0, etc.) before serving
cached content.

## How it works

The VMOD implements the standard OIDC Authorization Code flow using a
built-in Varnish backend that generates redirect and error responses
directly — no `vcl_synth` state machine is needed:

1. An unauthenticated request arrives at a protected path.
2. VCL calls `session_valid()` which returns `FALSE` (no valid cookie).
3. VCL sets `req.backend_hint = provider.backend()` and returns `pass`.
4. The built-in backend generates a 302 redirect to the identity provider,
   setting the state cookie automatically.
5. The user authenticates and is redirected back to the callback path.
6. VCL routes the callback to the same backend, which exchanges the code
   for an ID token, validates it, and returns a 302 redirect with the
   encrypted session cookie.
7. Subsequent requests include the session cookie; `session_valid()` returns
   `TRUE` and individual claims are available via `claim()`.

## Session model

Sessions are stateless and cookie-based. The full set of ID token claims is
AES-256-GCM encrypted and stored directly in the cookie. No external session
store (Redis, memcached, etc.) is needed. Sessions survive Varnish restarts
and work across multiple Varnish instances sharing the same `cookie_secret`.

Session revocation is not supported in v1 — a session is valid until it
expires.

## Authentication, not authorization

vmod-oidc handles **authentication** — verifying *who* a user is. It does not
handle **authorization** — deciding *what* an authenticated user is allowed to
do. Once a session is established, all authenticated users are treated equally.
Any access-control decisions based on claims (roles, groups, email domain, etc.)
must be implemented in VCL or at the origin.

## Security properties

- **Fail-closed**: all validation failures return empty string or `FALSE`.
  Partial data is never leaked.
- **Issuer validation**: always enabled; the `iss` claim must match the
  discovery document.
- **Nonce binding**: the `nonce` in the ID token must match the nonce stored
  in the state cookie.
- **Cookie protection**: session and state cookies are `HttpOnly`,
  `SameSite=Lax`, `Path=/`, and `Secure` by default. Contents are encrypted
  and authenticated with AES-256-GCM.
- **JWKS rotation**: unknown key IDs trigger an automatic JWKS refresh with
  exponential backoff.

## Prerequisites

1. Register an OAuth 2.0 / OIDC application with your identity provider.
2. Set the authorized redirect URI to your callback path
   (e.g. `https://www.example.com/oidc/callback`).
3. Generate a 32-byte cookie secret:
   ```
   openssl rand -hex 32
   ```
4. Set environment variables before starting Varnish:
   ```sh
   export OIDC_CLIENT_ID="your-client-id"
   export OIDC_CLIENT_SECRET="your-client-secret"
   export OIDC_COOKIE_SECRET="<output from openssl rand -hex 32>"
   ```

## VCL example

A complete example protecting paths under `/app/` with Google as the
identity provider:

```vcl
import oidc;
import std;

backend default {
    .host = "127.0.0.1";
    .port = "8080";
}

sub vcl_init {
    new google = oidc.provider(
        discovery_url = "https://accounts.google.com/.well-known/openid-configuration",
        client_id     = std.getenv("OIDC_CLIENT_ID"),
        client_secret = std.getenv("OIDC_CLIENT_SECRET"),
        redirect_uri  = "https://www.example.com/oidc/callback",
        cookie_secret = std.getenv("OIDC_COOKIE_SECRET"),
        cookie_name   = "__oidc_session",
        cookie_ttl    = 3600s,
        scopes        = "openid email profile"
    );
}

sub vcl_recv {
    # --- OIDC callback ---
    # The built-in backend handles state validation, code exchange,
    # and redirects the user back with a session cookie.
    if (req.url ~ "^/oidc/callback") {
        set req.backend_hint = google.backend();
        return (pass);
    }

    # --- Protected paths ---
    # Everything under /app/ requires a valid session.
    # Unauthenticated users are redirected to the identity provider
    # by the built-in backend.
    if (req.url ~ "^/app/") {
        if (!google.session_valid()) {
            set req.backend_hint = google.backend();
            return (pass);
        }

        # Pass user identity to the origin as headers.
        set req.http.X-User-Email = google.claim("email");
        set req.http.X-User-Name  = google.claim("name");
        set req.http.X-User-Sub   = google.claim("sub");
    }

    # Everything else (/, /static/, /health, etc.) is public.
}
```

## Pre-built releases

Each tagged release on GitHub publishes four binaries, one per
supported (Varnish version × CPU architecture) combination:

```
libvmod_oidc-varnish<VER>-amd64.so
libvmod_oidc-varnish<VER>-arm64.so
```

Pick the binary matching your installed Varnish version and host
architecture — the VMOD ABI is tied to the Varnish version it was
linked against, so a `9.0.0` binary will not load on a `9.0.1` Varnish
and vice versa.

Currently supported: Varnish `9.0.0` and `9.0.1`, on `amd64` and
`arm64`. Policy is to ship binaries for the current and previous
Varnish point release; older versions are dropped from the matrix when
a new one ships.

Need a build for a different Varnish version? The matrix is one line in
`.github/workflows/build.yml`:

```yaml
matrix:
  varnish: ['9.0.0', '9.0.1']
  arch: [amd64, arm64]
```

Add or edit a value, push, tag, and the release workflow produces the
new binaries. The container image (`varnish:<VER>`) and the apt pin
(`varnish-dev=<VER>-1~trixie`) are both derived from the matrix value.
See `CLAUDE.md` for verification steps and the `-1~trixie` pin caveat
(the apt repo defaults to "latest", which conflicts with the held
runtime in the version-pinned container).

## Building from source

```sh
cargo build --features vmod
```

This produces a shared library (`libvmod_oidc.so` on Linux,
`libvmod_oidc.dylib` on macOS) in `target/debug/` (or `target/release/`
with `--release`).

Load it in VCL with:

```vcl
import oidc from "/path/to/libvmod_oidc.so";
```

## Running tests

```sh
cargo test                     # Unit tests
cargo test --features vmod     # Including VMOD-specific tests
```

## API reference

See [API.md](API.md) for the full constructor and method reference.
