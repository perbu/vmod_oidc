# VTC Tests

Current VTC coverage:

- `test-01-redirect-unauthenticated.vtc`
- `test-02-valid-session.vtc`
- `test-03-expired-session.vtc`
- `test-04-invalid-cookie.vtc`
- `test-05-callback-valid.vtc`
- `test-06-callback-invalid-state.vtc`
- `test-07-callback-invalid-token.vtc`
- `test-08-claims.vtc`
- `test-09-public-path.vtc`
- `test-10-multiple-providers.vtc`

## Running VTC manually

Build the VMOD first:

```sh
cargo build --features vmod
```

Then invoke `varnishtest` with `vmod` pointing at the built dylib, for example:

```sh
bin/varnishtest/varnishtest -D vmod=$(pwd)/target/debug/libvmod_oidc.dylib tests/test-01-redirect-unauthenticated.vtc
```
