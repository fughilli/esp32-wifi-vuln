# Coordinated disclosure — ESP32-C6 WiFi/BT stack

Two memory-safety findings in the closed ESP32-C6 WiFi/BT stack + the ESP-IDF
mbedtls crypto port, from a from-source reverse-engineering audit
(`docs/audit/`). Both are **remotely reachable** on a widely-deployed part.

## Policy: report to Espressif first, do NOT publish first

These affect millions of shipped devices with no fix available. Publishing the
exploit details as 0-day would endanger users. We follow **coordinated
disclosure**:

1. **Report privately to Espressif PSIRT** (`security@espressif.com`, and/or the
   Espressif bug-bounty) with the reports below.
2. **Grace period** — industry-standard ~90 days (negotiable with the vendor) for
   a fix + advisory + CVE assignment.
3. **Publish** the writeup + PoC only after a fix ships or the window lapses,
   coordinated with the vendor's advisory.

Until then, keep the exploit specifics (the crafted-frame builder / patched
injector in `poc/mbssid/`) in the private submission; this repo's public copy
should carry the *analysis* but not a turnkey weapon.

## Reports

| ID | Title | Class | Severity | Status |
| --- | --- | --- | --- | --- |
| [ESP-001](ESP-001-mbssid-heap-overflow.md) | MBSSID beacon-reconstruction heap OOB write | remote pre-auth heap overflow | High | drafted — submit to PSIRT |
| [ESP-002](ESP-002-aes-gcm-output-size.md) | `esp_aes_gcm_update` drops the `output_size` bounds check | output-buffer overflow (API) | Medium | drafted — submit to PSIRT |

## Fixes we're building
The from-source heapless stack (`stack/esp32c6-wifi/`) is the structural fix for
these classes (capacity-typed buffers, zero-alloc RX path). For the vendor, the
minimal fixes are the bounds checks named in each report.
