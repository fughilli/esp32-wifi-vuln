# PSIRT submission — draft email

**To:** security@espressif.com
**Cc:** (Espressif bug-bounty portal, if used in parallel)
**Subject:** Coordinated disclosure — two memory-safety issues in the ESP32-C6 Wi-Fi / crypto stack (pre-auth heap OOB write + hardware-GCM bounds check)

---

Hello Espressif PSIRT,

I'm reporting two memory-safety issues found in the ESP32-C6 Wi-Fi / crypto stack
under coordinated disclosure. I'd like to share the full technical write-ups and
proof-of-concept privately and give you time to remediate before any public
disclosure. A short summary of each is below; the complete reports (root cause,
reachability, silicon validation, and suggested fixes) are attached.

## ESP-001 — Multiple-BSSID beacon reconstruction: remote pre-association heap out-of-bounds write

- **Component:** ESP32-C6 Wi-Fi stack (`libnet80211`), the Multiple-BSSID (MBSSID)
  element handling on the receive path.
- **Class / severity:** Remote heap OOB write (CWE-787), CVSS:3.1
  AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H ≈ **8.1 (High)**.
- **Summary:** When a received beacon / probe-response carries an MBSSID element,
  the stack synthesizes a standalone beacon for each non-transmitted BSSID profile
  into a fixed pooled buffer and appends the merged information elements **without
  a destination-bounds check**. A single crafted MBSSID beacon whose
  reconstruction exceeds the pool buffer causes an out-of-bounds heap write. No
  association, key, or user interaction is required — a victim only needs to be
  scanning or connected in range.
- **Impact:** Remote, pre-association heap corruption (DoS at minimum; a candidate
  for RCE given control over the overflow length and partial content).
- **Validation:** Analyzed to root cause, cross-checked against the sibling
  fragment-reassembly path (which performs the analogous bound correctly), and
  reproduced on real ESP32-C6 hardware: a crafted MBSSID beacon is received and
  parsed by the target on the affected path. Full details + PoC attached.

## ESP-002 — `esp_aes_gcm_update` drops the `output_size` bounds check

- **Component:** ESP-IDF mbedTLS hardware-crypto port
  (`components/mbedtls/port/aes/esp_aes_gcm.c`), the AES-DMA / hardware-GCM path.
- **Class / severity:** Output-buffer overflow via a missing API bounds check
  (CWE-787 / CWE-20), CVSS:3.1 AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H ≈ **6.x
  (Medium)**; reachability is API-consumer-dependent.
- **Summary:** mbedTLS 3.x added an `output_size` parameter to
  `mbedtls_gcm_update()` so implementations can reject an undersized output buffer
  (`output_size < input_length → MBEDTLS_ERR_GCM_BAD_INPUT`). The ESP hardware-GCM
  replacement accepts `output_size` but only honors it on the software-fallback
  path; the hardware path writes `input_length` bytes regardless. Any caller that
  relies on the documented bounds check (safe on upstream mbedTLS) gets a silent
  output-buffer overflow on ESP targets.
- **Suggested fix:** add the upstream `if (output_size < input_length) return
  MBEDTLS_ERR_GCM_BAD_INPUT;` guard to `esp_aes_gcm_update()` (and
  `esp_aes_gcm_finish()`), and audit the sibling ALT ports for the same omission.

## Process

- I'm following coordinated disclosure: report to you first, an industry-standard
  ~90-day grace period (negotiable), and publish only after a fix ships or the
  window lapses.
- I'm happy to work with you on affected-version confirmation, CVE assignment, and
  fix verification, and to re-test candidate fixes on hardware.
- Attached: `ESP-001-mbssid-heap-overflow.md`, `ESP-002-aes-gcm-output-size.md`,
  the per-finding analysis, and the proof-of-concept (`poc/`).

Please confirm receipt and let me know your preferred channel for the encrypted
attachments (PGP key / bug-bounty upload).

Thank you,
(name / contact / PGP fingerprint)

---

## Sending checklist

- [ ] Fill in reporter name / contact / PGP fingerprint.
- [ ] Attach `ESP-001-*.md`, `ESP-002-*.md`, `docs/audit/`, and `poc/` (zip;
      encrypt to Espressif's PGP key or upload via the bug-bounty portal).
- [ ] Record the send date here to start the ~90-day clock:  ____________
- [ ] Log any PSIRT ticket / CVE IDs returned:  ____________
