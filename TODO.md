# TODO

## Reduce heap allocations in request paths

### Return `&str` from VMOD methods using `WsStrBuffer`

Instead of returning `String` from VMOD methods (which the macro then copies into
workspace), write directly to workspace using `ctx.ws.vcl_string_builder()` and
return `VCL_STRING`. This avoids the heap alloc → workspace copy → heap free
cycle but requires splitting the library API into a workspace-aware VMOD layer
or having the core library accept a writer/buffer to write into.

**Assessment (after module split):** `vmod.rs` is now the natural place for
workspace-aware methods. The pattern would be: VMOD method gets `WsStrBuffer`
from `ctx.ws.vcl_string_builder()`, core `Provider` method writes into it via
`&mut impl Write`, VMOD returns `VCL_STRING` directly.

Practical limitation: most string construction happens inside library calls we
don't control (`Url::to_string()`, `serde_json::to_string()`, `format!()`).
Methods where direct workspace writing would actually skip a heap allocation:

- `callback_code()` / `callback_state()` — extract a query param (but `url`
  crate returns `Cow<str>`, already borrowed in many cases)
- `claim()` — for string claims, could copy directly; for serialized claims,
  serde returns owned `String`
- `build_set_cookie()` — string formatting, could use `write!()` into buffer

The saving per request is one or two small heap allocs (~100–500 bytes). Worth
doing eventually for a hot-path VMOD, but not urgent.

### Use workspace for crypto outputs

The crypto crates (`aes-gcm`, `base64`) return owned `Vec<u8>` — those heap
allocations can't be avoided. However, the *downstream* allocation (building a
`String` from the crypto output, which the VMOD macro then copies into workspace)
can be eliminated:

- Use `ctx.ws.copy_blob(&ciphertext)` to copy a `Vec<u8>` directly into
  workspace, or `vcl_blob_builder` to build incrementally.
- For string outputs (e.g., base64-encoded cookies), use `vcl_string_builder`
  and write the base64 directly into it via `base64::write::EncoderWriter`,
  skipping the intermediate `String`.

The `Vec<u8>` from crypto becomes short-lived (allocate, copy to workspace,
drop). Saves one heap allocation per encrypt/decrypt operation. Combine with
the `WsStrBuffer` work above for maximum effect.
