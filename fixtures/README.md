# Test Fixtures

This directory contains generated keys, JWT fixtures, and encrypted cookie fixtures used by OIDC tests.

Regenerate with:

```sh
cargo run -p gen-test-fixtures -- --output fixtures/
```

To generate issuer-aligned tokens for callback tests, pass an explicit issuer:

```sh
cargo run -p gen-test-fixtures -- --output fixtures/ --issuer http://127.0.0.1:18080
```

`v1` rule reminder: issuer validation is always enabled. Valid-path callback tests must use tokens whose `iss` claim matches discovery issuer at runtime.

Cookie fixtures in `fixtures/cookies/` are deterministic AES-GCM values generated with the test `cookie_secret`:

- `valid-session.cookie`
- `expired-session.cookie`
- `state-valid.cookie`
- `state-invalid-return-to.cookie`
- `state-for-expired-token.cookie`
- `state-wrong-audience.cookie`
- `state-wrong-issuer.cookie`
- `state-wrong-signature.cookie`
- `state-missing-claims.cookie`
