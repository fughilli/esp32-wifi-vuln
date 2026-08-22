# esp32-wifi-vuln — coordinated disclosure (PRIVATE)

**Private.** Vulnerability disclosure material for the ESP32-C6 WiFi/BT stack,
prepared for coordinated disclosure to Espressif. Do not make public until the
coordinated-disclosure window closes (see `docs/disclosure/README.md`).

## Contents

- `docs/disclosure/` — the reports to send to Espressif PSIRT:
  - `ESP-001-mbssid-heap-overflow.md` — remote pre-association heap OOB write in
    the MBSSID beacon-reconstruction path.
  - `ESP-002-aes-gcm-output-size.md` — missing output-buffer bounds check in the
    hardware-GCM port.
  - `README.md` — the disclosure policy / timeline.
- `docs/audit/` — the full analysis trail behind each finding (methodology +
  per-finding RE writeups).
- `poc/mbssid/` — proof-of-concept: crafted-MBSSID-beacon builder/injector
  (`inject_mbssid.py` for a monitor-mode radio; `mbssid_attacker.cpp` for an ESP
  injector) and the instrumented target (`mbssid_target.cpp`).
- `firmware/` — the buildable exploit/target firmware as integrated in the
  bench-firmware tree (see `BUILD.bazel.reference` for the target wiring).
- `tools/hitl/run_mbssid_poc.sh` — the 2-DUT reproduction driver.

## Reproduction

The PoC was validated on a hardware-in-the-loop bench (two ESP32-C6 DUTs, plus a
monitor-mode injector for frames above the on-chip TX size cap). See
`docs/disclosure/ESP-001-*.md` (reachability / silicon-validation section) and
`poc/mbssid/README.md`.

## Scope

The clean-room defensive reimplementation that neutralizes these findings is
maintained separately (it carries none of this material) and is not part of this
repository.
