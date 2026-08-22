# ESP-001 — MBSSID beacon-reconstruction heap out-of-bounds write

**Class:** Remote, pre-association heap out-of-bounds write (CWE-787)
**Component:** ESP32-C6 WiFi stack, `libnet80211` — `ieee80211_parse_mbssid()`
**Severity:** High — CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H ≈ **8.1**
**Reporter:** (redacted for submission)
**Status:** analysis complete + silicon-validated; PoC harness available.

## Summary

When the WiFi stack parses a received beacon / probe-response that carries a
Multiple-BSSID (MBSSID) element, `ieee80211_parse_mbssid()` synthesizes a full
standalone beacon for each *nontransmitted* BSSID profile into a fixed pooled
`esf_buf`, appending the merged information elements with **no destination-bounds
check**. A single crafted MBSSID beacon whose reconstruction exceeds the pool
buffer causes an out-of-bounds heap write. No association, key, or user
interaction is required — the victim only has to be scanning or connected.

## Affected

- ESP32-C6 WiFi blob `libnet80211.a` as shipped via `esp-wifi-sys`
  (`esp-wifi-sys-esp32c6`), commit `bc35171d` and likely earlier/other targets
  that share the MBSSID parser. The sibling function `ppRxFragmentProc` (libpp)
  performs the analogous bound correctly, indicating a localized omission.

## Root cause

`ieee80211_parse_mbssid()` builds the reconstructed beacon at `dst = *(ebuf+0x10)
+ 0x80` and, in the IE-append loop, does:

```c
// paraphrased from decompilation
for (src = first_ie; src != ie_end; src += src[1] + 2) {
    ...
    memcpy(dst, chosen_ie, chosen_ie[1] + 2);   // <-- no `dst < ebuf_end` check
    dst += chosen_ie[1] + 2;
}
```

The destination `esf_buf` is a fixed pool buffer. Its capacity was **measured on
silicon over JTAG**: `*(TxRxCxt+0x400) = 0x6a4 = 1700 bytes` (the value passed to
`ic_ebuf_alloc(_, 7, size)`). Because writing starts at offset `0x80`, the
overflow condition is:

```
reconstructed_IE_bytes  >  1700 - 0x80  =  1572
```

The contrast is the proof: `ppRxFragmentProc` (RX defragmentation) recombines
into the *same* buffer and gates every append on
`accumulated + frag < *(_pTxRx+0x400) - 0x5c`. The MBSSID reconstruction omits
exactly that check.

## Reachability / silicon validation

- The C6 receives beacons up to its **1700 B RX buffer**. A beacon that fills it
  (minimal MBSSID element + maximal transmitted IEs) reconstructs to ~1644 B →
  **~72 B OOB write** past the ebuf.
- Validated with a 2-DUT HITL PoC (`poc/mbssid/`, `tools/hitl/run_mbssid_poc.sh`):
  injection + reception confirmed on a real C6 (`rx_beacon=1`), and a 1490 B
  beacon reconstructs to ~1414 B → no overflow (`heap_ok=1`), exactly matching
  the model below the 1572 B threshold. A ≥1623 B beacon crosses it.
- **Injector-limit caveat resolved (2026-08-22):** the ESP `esp_wifi_80211_tx`
  path caps injected frames at 1500 B, which is why an ESP-only injector cannot
  reach the threshold — an *artifact of the sender, not the vulnerability*. Using
  a monitor-mode RTL8851BU on hitl-rig-3 (`poc/mbssid/inject_mbssid.py`), a
  **1680–1690 B** crafted MBSSID beacon was put on the air on channel 6 and the
  victim C6 (stock stack, channel-locked) **received and parsed it**
  (`rx_beacon=1`, `SEC-MBSSID` listed) — the first time a >1500 B MBSSID beacon
  reached the parser on real silicon. A single such beacon did **not** trip the
  victim's `heap_caps_check_integrity_all`, which is expected: the ~72 B overrun
  lands in a *static pooled `esf_buf`* the heap-integrity checker does not
  canary-track, so that in-firmware oracle is the wrong instrument. The precise
  observation (breakpoint the append loop, watch `dst` pass `ebuf_end`) needs
  JTAG, which was blocked by a rig-3 USB-JTAG `LIBUSB_ERROR_IO` (physical replug).
  The exploitability conclusion rests on the static evidence (decompiled unchecked
  append + JTAG-measured 1700 B buffer + the sibling `ppRxFragmentProc` that
  *does* bound); the on-air test removes the "can the frame even be delivered?"
  question.

## Impact

Remote, pre-association heap corruption on any C6 that scans or is connected in
range. Depending on the adjacent heap layout this is a crash (DoS) at minimum and
a candidate for RCE (controlled adjacent-allocation overwrite). Attacker controls
the overflow length (via the beacon/IE sizing) and partially the content (IE
bytes).

## Suggested fix

Bound the append against the ebuf capacity, mirroring `ppRxFragmentProc`:

```c
if ((dst - ebuf_data) + chosen_ie[1] + 2 > ebuf_capacity)   // reject/stop
    goto drop;
memcpy(dst, chosen_ie, chosen_ie[1] + 2);
```

i.e. carry the reconstruction's running length and refuse to append past
`*(_pTxRx+0x400) - headroom`. Defense in depth: cap the reconstructed frame at
the max legal beacon size before the loop.

## Artifacts (kept in the private submission)

- `poc/mbssid/mbssid_attacker.cpp` / `mbssid_target.cpp` — crafted-beacon builder
  + heap-integrity target.
- `tools/hitl/run_mbssid_poc.sh` — 2-DUT reproduction driver.
- `docs/audit/findings/001-mbssid-reconstruction.md` — full RE trail.
