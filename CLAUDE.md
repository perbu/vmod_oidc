# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

vmod-oidc is a Varnish VMOD (Varnish Module) written in Rust that implements OpenID Connect authentication. It allows Varnish Cache to act as an OIDC Relying Party. The core OIDC logic lives in `src/lib.rs` as a standalone library; the Varnish VMOD bindings are feature-gated behind `--features vmod`.

## Build Commands

```sh
cargo build                    # Core library only
cargo build --features vmod    # With Varnish VMOD bindings
cargo test                     # Unit tests (uses mockito for HTTP mocking)
cargo test --features vmod     # Unit tests including VMOD-specific code
```

### Test Fixtures

Fixtures (RSA keys, pre-signed JWTs, encrypted cookies) live in `tests/fixtures/`. Regenerate with:

```sh
cargo run -p gen-test-fixtures -- --output tests/fixtures/
cargo run -p gen-test-fixtures -- --output tests/fixtures/ --issuer http://127.0.0.1:18080  # issuer-aligned tokens
```

### VTC Integration Tests

VTC (Varnish Test Case) files are in `tests/`. They require `varnishtest` and a built VMOD:

```sh
cargo build --features vmod
bin/varnishtest/varnishtest -D vmod=$(pwd)/target/debug/libvmod_oidc.dylib tests/test-01-redirect-unauthenticated.vtc
```

## Architecture

The crate is split into modules:

| File | Contents |
|------|----------|
| `src/lib.rs` | Module declarations, `ProviderConfig`, `Provider`, `AuthorizationStart`, integration tests |
| `src/error.rs` | `OidcError` enum |
| `src/crypto.rs` | `CookieCipher`, `StateCookie`, `decode_cookie_secret()` |
| `src/jwks.rs` | `DiscoveryDocument`, `JwksCache`, `RsaKeyMaterial`, `TokenResponse`, `fetch_discovery()`, `fetch_jwks_cache()`, `parse_max_age()` |
| `src/helpers.rs` | `cookie_value()`, `query_param()`, `derive_return_to()`, `validate_return_to()`, `random_token()`, `build_set_cookie()`, `now_secs()` |
| `src/vmod.rs` | `provider` wrapper struct, `#[varnish::vmod] mod oidc`, Varnish context helpers (feature-gated behind `vmod`) |

Key types:

- **`ProviderConfig`** — Configuration for an OIDC provider (client_id, secrets, URLs, TTLs)
- **`Provider`** — Runtime state: holds HTTP client, JWKS cache (behind Mutex), discovery endpoints. Created via `Provider::new()` which fetches discovery document and JWKS at init time (fail-closed).
- **`OidcError`** — Error enum. All public methods that can fail return `Result<_, OidcError>`.

Internal types are `pub(crate)` and re-exported in `lib.rs` for use across modules.

### Session Model

Stateless, cookie-based. Session data is AES-256-GCM encrypted and stored directly in the cookie. Format: `v1.` + base64url(nonce || ciphertext || GCM tag). No external session store.

### Security Invariants

- **Fail-closed**: All validation failures return empty string or `false` — never leak partial data.
- **Issuer validation always enabled**: No `skip_issuer_check` mode in v1.
- **Claims size limit**: 3072 bytes max serialized JSON.
- **Return-to path limit**: 2048 bytes, must be relative (no scheme/host).

### Feature Flags

- `default = []` — Pure Rust library, no Varnish dependency
- `vmod` — Enables `varnish-rs` VMOD FFI bindings
- `vtc-tests` — Implies `vmod`, enables VTC test support

## Versioning

Versions follow semver and are tracked in `Cargo.toml`. When bumping the version:

1. Bump `version` in `Cargo.toml` as part of the feature/fix commit.
2. After pushing, create a git tag on that exact commit: `git tag vX.Y.Z <commit>` and push it: `git push origin vX.Y.Z`.
3. The tag must match the `Cargo.toml` version (e.g. version `0.1.2` → tag `v0.1.2`).
4. The GitHub Release workflow triggers on tags, so the tag is what triggers the release build.

Never tag a commit that doesn't contain the matching version in `Cargo.toml`.

## Specification

`spec.md` contains normative v1 rules not covered elsewhere: token validation requirements, HTTP timeouts, state cookie internals, the VTC test plan, and out-of-scope items. For the VMOD interface and VCL examples, see README.md.
