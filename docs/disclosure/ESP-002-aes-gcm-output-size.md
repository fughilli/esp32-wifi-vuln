# ESP-002 — `esp_aes_gcm_update` ignores `output_size` (missing bounds check)

**Class:** Output-buffer overflow via missing API bounds check (CWE-787 / CWE-20)
**Component:** ESP-IDF mbedtls hardware-crypto port —
`components/mbedtls/port/aes/esp_aes_gcm.c`, `esp_aes_gcm_update()` (and
`esp_aes_gcm_finish()`), the `SOC_AES_SUPPORT_DMA` / `MBEDTLS_GCM_ALT` path.
**Severity:** Medium — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H ≈ **6.x**
(reachability is API-consumer-dependent; see below). Open-source component.
**Status:** confirmed at source level; wiring confirmed (`MBEDTLS_GCM_ALT` maps
`mbedtls_gcm_update → esp_aes_gcm_update`).

## Summary

mbedtls 3.x added the `output_size` parameter to `mbedtls_gcm_update()` so
implementations can reject an undersized output buffer
(`output_size < input_length → MBEDTLS_ERR_GCM_BAD_INPUT`). The ESP hardware-GCM
replacement takes `output_size` but **only uses it on the software-fallback
path**; the hardware path writes `input_length` bytes to `output` regardless.
Any caller that relies on the documented bounds check (as the upstream contract
guarantees) gets a silent output-buffer overflow on ESP targets.

## Root cause

```c
int esp_aes_gcm_update(ctx, input, input_length, output, output_size, output_length) {
    ...
#if defined(MBEDTLS_GCM_NON_AES_CIPHER_SOFT_FALLBACK)
    if (ctx->ctx_soft != NULL)
        return mbedtls_gcm_update_soft(..., output, output_size, output_length); // only use
#endif
    ...
    *output_length = input_length;          // no `output_size < input_length` guard
    ...
    esp_aes_crypt_ctr(&ctx->aes_ctx, input_length, ..., input, output); // writes input_length bytes
    ...
}
```

Upstream `mbedtls_gcm_update()` (and the ESP soft-fallback it delegates to) do
the `output_size < input_length` check; the ESP hardware path dropped it — a
hardening regression from an older port not updated when mbedtls added the
parameter. The AAD path in the same file *does* bound-check
(`if (aad_len > DMA_DESCRIPTOR_BUFFER_MAX_SIZE...)`), so this is a localized gap.

## Reachability

- **Not** reachable via mbedtls's own TLS record layer (it sizes the GCM output
  buffer `== input_length`, so `output_size >= input_length` always holds).
- **Reachable** by any code that calls `mbedtls_gcm_update()` directly with a
  fixed output buffer and trusts the documented `output_size` rejection —
  application AEAD framing, other libraries, portable code that is safe on stock
  mbedtls but not here. That divergence is the risk.

## Suggested fix

Add the upstream guard to both functions:

```c
if (output_size < input_length) {
    return MBEDTLS_ERR_GCM_BAD_INPUT;
}
```

in `esp_aes_gcm_update()` (and the analogous guard in `esp_aes_gcm_finish()`),
before any write to `output`. Audit the sibling ALT ports (`esp_aes_xts.c`, the
CBC/CTR block ports) for the same omission.

## Affected

ESP-IDF mbedtls port on all `esp32xx` targets with AES-DMA + hardware GCM
(`CONFIG_MBEDTLS_HARDWARE_GCM`), not just the C6. Verified against the IDF
version vendored by the firmware under test (v5.5.x).
