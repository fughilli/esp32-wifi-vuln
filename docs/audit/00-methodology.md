# Security audit of the closed ESP32-C6 WiFi/BT stack

Goal: decompile the whole stack and audit it for the vulnerability. This file is
the method + index; per-finding write-ups live in `docs/audit/findings/`.

## Ground rules

- **Public repo** — do **not** commit raw decompiled proprietary C (`out/` is
  gitignored). Findings describe the bug in our own words with the *minimal*
  snippet needed to show it, plus the function name + blob so a reviewer can
  regenerate the decomp locally.
- **Report only verified findings.** A `vuln_scan` hit is a *lead*, not a bug.
  Each candidate is confirmed by reading the decompilation and, where possible,
  reproduced/observed on hardware (HITL JTAG) before it graduates to a finding.

## Attack surface (priority order)

Remote, pre-association, attacker-controlled input is the crown jewel:

1. **802.11 management-frame parsing** (`libnet80211`): beacon/probe/auth/assoc
   IE parsing, `ieee80211_*_input`, scan-result handling. Classic overflow turf.
2. **EAPOL / 4-way handshake** (`libnet80211` + `libwpa_supplicant`): key data /
   KDE parsing. (wpa_supplicant is open upstream — diff against it, don't just
   trust the blob.)
3. **BLE link-layer / HCI / L2CAP / ATT** (`libble_app`, `libbtbb`): PDU length
   handling, ATT MTU, L2CAP reassembly.
4. **WiFi RX datapath / A-MPDU reassembly** (`libpp`): `hal_mac_rx`, defrag.
5. **espnow / mesh / smartconfig** (`libespnow`, `libmesh`, `libsmartconfig`):
   smaller, often sloppier parsers.

## Pipeline

```
# 1. decompile a blob (all functions):
tools/ghidra/analyze_lib.sh targets/esp32c6/libnet80211.a out/net80211 '.*'
# 2. rank by memory-safety red flags:
tools/audit/vuln_scan.py out/net80211/decomp --csv out/net80211_audit.csv --top 60
# 3. (fast pre-decomp triage) who calls a copy sink:
tools/audit/xref_callers.py targets/esp32c6/libnet80211.a --surface-only
# 4. read the top candidates' decomp, confirm the bug, write it up.
```

## What a real bug looks like here

- `memcpy(stack_buf, frame + off, len)` where `len` comes from a frame field
  with no bound against `sizeof(stack_buf)` — the archetypal IE/KDE overflow.
- length arithmetic that underflows (`ie_len - hdr`) then feeds a copy.
- an element/index taken from the frame used to index a fixed array unchecked.
- reassembly/defrag that accumulates fragments past the buffer.

## Findings index

_(none confirmed yet — decomp in progress)_

| ID | Blob | Function | Class | Status |
| --- | --- | --- | --- | --- |
| [001](findings/001-mbssid-reconstruction.md) | libnet80211 | `ieee80211_parse_mbssid` | heap overflow (remote) | EXPLOITABLE remote OOB write (buf=1700 JTAG-measured; needs >1500B beacon) |
| [002](findings/002-esp-aes-gcm-output-size.md) | idf mbedtls port | `esp_aes_gcm_update` | output-buf overflow (missing bounds check) | confirmed (code); API-consumer reach |

## Audited & cleared (no bug — coverage trail)

The scanner flags any variable-length copy; most turn out bounded. Confirmed safe:

| Blob | Function | Why cleared |
| --- | --- | --- |
| libnet80211 | `sta_recv_ctl` | 8-byte buf only ever gets ≤4-char literals (`NDPA`/`TRIG`/`BFRP`) |
| libnet80211 | `hostap_recv_mgmt` | RSN-IE copy (`+0x33`) gated by `ie_len < 0x3f` before a ≤64B copy |
| libnet80211 | `ieee80211_parse_he_mu_edca` | four *constant* 3-byte copies (false positive) |
| libpp | `ppRxFragmentProc` | reassembly appends gated on `acc+frag < *(_pTxRx+0x400)-0x5c` |
| idf mbedtls | AES-DMA descriptor core | descriptor-count calc + per-desc max-size + cache alignment; AAD bounded |
| libble_app | `r_ble_lll_conn_decrypt_cipher_data` | PDU len is a byte, `<5` reject, decrypts ≤251 into 264B buf |
| libble_app | `r_ble_lll_rxpdu_copy` | each copy clamped to mbuf `trailingspace` (NimBLE mbuf chain) |
| libble_app | `r_ble_ll_hci_send_ext_adv_report` | adv data fragmented per-HCI-report, each copy `≤229` (`& 0xff`) |

> The contrast is the point: sibling RX paths bound against the same buffer
> capacity that `ieee80211_parse_mbssid` (001) does not.
