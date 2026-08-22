# Finding 001 PoC — 2-DUT HITL MBSSID overflow

Authorized security testing, isolated HITL bench, own hardware.

- **Buildable firmware** lives in the splanc monorepo at `firmware/secaudit/`
  (needs the `@embedded` esp-idf toolchain). The `.cpp` here are mirrored copies
  for review; `BUILD.bazel.txt` is the build wiring.
- **Driver:** `../../tools/hitl/run_mbssid_poc.sh` — reserves both C6 DUTs on
  hitl-rig-3, flashes `mbssid_target` + `mbssid_attacker`, runs a benign baseline
  then the malicious beacon, and greps the target serial for heap corruption /
  panic.

## Design
- `mbssid_target`: STA + continuous scan → received beacons are parsed by
  `ieee80211_parse_mbssid()`. Each cycle runs `heap_caps_check_integrity_all()`
  and prints `heap_ok=`.
- `mbssid_attacker`: builds a beacon with an MBSSID element whose nontransmitted
  profile + inflated transmitted IE set make the reconstruction exceed the
  ~1.6 KB `esf_buf`, and injects it via `esp_wifi_80211_tx()`.
- Overflow knobs (iterate on-bench): `kTxPadTarget`, `kProfileExtra`.

## Run
    esp32-reverse/tools/hitl/run_mbssid_poc.sh

## Sender patch — lift the 1500 B injection cap (finding-001 live crash)

`esp_wifi_80211_tx` rejects len>1500 via the blob-internal
`ieee80211_raw_frame_sanity_check()` (`0x5dc < len`). The `mbssid_attacker_patched`
target defines its own `ieee80211_raw_frame_sanity_check()->0`; the linker
resolves the blob's internal call to ours (`--allow-multiple-definition`),
bypassing the check so we inject a >1500 B beacon toward the target's 1700 B RX
buffer.

    tools/hitl/run_mbssid_poc.sh  # (point ATK at attacker_patched_flashbundle.tar)

Caveat: the raw-TX path still copies into a ~1600 B type-1 esf_buf, so this
reaches ~1600 B — right at the ~1623 B overflow threshold (marginal). A fully
unbounded injector (rig RTL8851BU / a monitor-mode card replaying the ~1650 B
frame) is the sure path. Exploitability itself is already proven analytically
(JTAG-measured 1700 B buffer + silicon-validated model); this is the live demo.
