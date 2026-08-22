# 002 — esp_aes_gcm_update ignores output_size (missing bounds check)

- **Component:** esp-idf mbedtls HW-crypto port (NOT a proprietary blob —
  open-source, Apache-2.0). `components/mbedtls/port/aes/esp_aes_gcm.c`,
  IDF v5.5.x, the `SOC_AES_SUPPORT_DMA` hardware path.
- **Functions:** `esp_aes_gcm_update()` (primary), `esp_aes_gcm_finish()` (same
  shape). These are the `MBEDTLS_GCM_ALT` replacements for
  `mbedtls_gcm_update()` / `_finish()`.
- **Class:** output-buffer overflow — missing API bounds check (hardening
  regression vs. upstream mbedtls).
- **Status:** CONFIRMED (code-level); reachability is API-consumer-dependent
  (see below) — honestly *not* a direct TLS-triggerable RCE.

## The bug

mbedtls 3.x added an `output_size` parameter to the streaming AEAD API precisely
so implementations can bounds-check the caller's output buffer. Upstream
`mbedtls_gcm_update()` does:

```c
if (output_size < input_length) {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
}
```

The ESP hardware port takes `output_size` but **only uses it in the soft-fallback
branch**; the hardware path never checks it:

```c
int esp_aes_gcm_update(ctx, input, input_length, output, output_size, output_length) {
    ...
#if defined(MBEDTLS_GCM_NON_AES_CIPHER_SOFT_FALLBACK)
    if (ctx->ctx_soft != NULL)
        return mbedtls_gcm_update_soft(..., output, output_size, output_length); // only place output_size is used
#endif
    ...
    *output_length = input_length;          // no `output_size < input_length` guard
    ...
    // writes input_length bytes into output, regardless of output_size:
    esp_aes_crypt_ctr(&ctx->aes_ctx, input_length, &nc_off, nonce_counter, stream, input, output);
    ...
}
```

`esp_aes_crypt_ctr` writes exactly `input_length` bytes to `output`. So a caller
that passes `output_size < input_length` — trusting the documented contract to
reject it — gets a silent overflow of `output` on ESP hardware that upstream
mbedtls (and the ESP soft-fallback) would have rejected.

## Reachability (honest)

- **Via TLS itself: no.** mbedtls's record layer sizes the GCM output buffer
  equal to the input length (GCM is a stream cipher, no expansion), so
  `output_size >= input_length` always holds internally.
- **Via direct API use: yes.** Any code that calls `mbedtls_gcm_update()` with a
  fixed/attacker-influenced-length pairing and relies on the `output_size` bounds
  check — application AEAD framing, other libraries — overflows on ESP targets
  but not on stock mbedtls. That divergence is the risk: portable code that is
  safe everywhere else is unsafe here.

## Recommendation / next

- Add `if (output_size < input_length) return MBEDTLS_ERR_GCM_BAD_INPUT;` (and
  the analogous guard in `esp_aes_gcm_finish`) to match upstream. Report upstream
  to Espressif (affects all esp32xx AES-DMA targets, not just C6).
- Confirm against the very latest IDF (may already be patched) and check the
  sibling ALT ports (`esp_aes_xts.c`, the CBC/CTR block ports) for the same
  output_size omission.
