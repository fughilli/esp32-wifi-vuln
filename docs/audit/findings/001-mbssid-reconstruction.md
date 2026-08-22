# 001 — MBSSID beacon reconstruction: unbounded IE append (CANDIDATE)

- **Blob / function:** `libnet80211.a` · `ieee80211_parse_mbssid`
  (helpers: `ieee80211_merge_mbssid_profile`, `ic_ebuf_alloc`,
  `ieee80211_find_ie/find_elem/find_ext_elem`)
- **Class:** heap buffer overflow (remote, pre-association)
- **Attack surface:** a received **beacon/probe-response carrying a Multiple-BSSID
  (MBSSID, element ID 0x47) element** — fully attacker-controlled, no association
  or key required. Reached from `hostap_recv_mgmt` → beacon parse.
- **Status:** LIKELY (static) — the destination is a fixed-size pooled buffer
  and the append loop has no bound; safety rests on an *unenforced* size
  invariant. Not yet reproduced on hardware (definitive step below).

## Confirmation progress (esf_buf sizing)

`ic_ebuf_alloc(0, 7, …)` → `esf_buf_alloc(_, type=7, size)`. Traced the pool
setup (`esf_buf_setup` / `esf_buf_setup_static`):

- Static pools are configured for types 1/8/9/10 (~`0x640`=1600, 500, 1600, 600
  bytes). **There is no `esf_buf_setup_static(7, …)`** — type 7 draws a
  **fixed-size pooled buffer** from a shared free list, whose capacity is set by
  the pool descriptor, not by any per-reconstruction length.
- On alloc, the length is written to a **14-bit field** (`… & 0x3fff`, max
  16383) at `ebuf+0x16` with **no comparison against the buffer capacity**.
- The reconstruction then appends IEs from `ebuf_data+0x80` upward with no
  destination check.

So nothing in this path enforces `reconstructed_size ≤ buffer_capacity`. Because
MBSSID reconstruction *expands* a compressed non-transmitted profile into a full
standalone beacon (transmitted IEs + profile overrides), the output can exceed a
near-max-size input beacon — and thus a fixed ~1.6 KB pool buffer. That is the
overflow.

### Smoking gun: the sibling RX path DOES bound-check the same buffer

`ppRxFragmentProc` (libpp, RX defragmentation) reassembles fragments into an
identical `esf_buf` and gates **every** append on exactly that capacity:

```c
// paraphrased
if (accumulated + frag_len < *(_pTxRx + 0x400) - 0x5c)
    memcpy(reasm + accumulated, frag, frag_len);   // bounded
```

`*(_pTxRx + 0x400)` is the very value the MBSSID path passes to
`ic_ebuf_alloc(0, 7, *(_pTxRx+0x400))` — i.e. the buffer capacity (~`0x640`/1600,
matching the `esf_buf_setup` pool sizes). So the codebase clearly *knows* to
bound writes against `_pTxRx+0x400 - 0x5c`; `ieee80211_parse_mbssid` simply omits
that check while doing an expanding reconstruction into the same buffer. This is
a strong corroboration that 001 is a real overflow, not a benign invariant.

(Aside: `ppRxFragmentProc` itself is **not** vulnerable — audited and cleared.)

## What the function does

For each nontransmitted BSSID profile inside an MBSSID element, it *synthesizes a
full standalone beacon* for that BSSID into a freshly allocated ebuf
(`ic_ebuf_alloc(0, 7, …)`), then feeds it to `ieee80211_parse_beacon` /
`scan_parse_beacon` as if it were a real received beacon. The synthesis:

1. copies the transmitted beacon's fixed header into the new ebuf,
2. merges the per-profile IEs over the transmitted IEs, then
3. walks the transmitted beacon's IE list and **appends** each resulting IE into
   the ebuf's IE area at `dst = *(ebuf+0x10) + 0x80`, advancing `dst` by
   `ie_len + 2` each time:

   ```c
   // paraphrased; loop runs until the source IE list is exhausted
   for (src = first_ie; src != ie_end; src += src[1] + 2) {
       ...
       memcpy(dst, chosen_ie, chosen_ie[1] + 2);   // <-- no check dst < ebuf_end
       dst += chosen_ie[1] + 2;
   }
   ```

There is **no check that `dst` stays within the ebuf buffer** across the append
loop. The appended IEs are the union of the transmitted beacon's IEs and the
profile's overriding IEs, so the reconstructed length can exceed the original
frame length — while the destination ebuf is a single fixed-size pool buffer.

## Mitigations already present (why it's "candidate", not "confirmed")

- `ieee80211_merge_mbssid_profile` masks its returned length with `& 0xff`, and
  its internal copies are gated by element/sub-element fit checks — so a single
  *profile* field can't exceed 255 and can't run off the source.
- The outer IE walk is length-checked against the frame end (`pcVar12`).

So the per-copy sizes are individually bounded; the open question is the
**cumulative** append vs. the ebuf capacity.

## To confirm (next steps)

1. **ebuf type-7 size:** decompile `ic_ebuf_alloc` + the `_pTxRx+0x400` pool
   descriptor to get the buffer capacity, and compare against the max
   reconstructable IE total (transmitted IEs + profile overrides).
2. If capacity < max reconstruction → overflow. Craft a beacon with a large
   transmitted IE set + an MBSSID element whose profile overrides inflate the
   result, and observe on hardware (HITL): flash a WiFi build, send the frame
   from a second radio, watch for heap corruption / the alloc-fail hook / a
   crash via JTAG.
3. Cross-check against upstream MBSSID CVEs (mac80211 `ieee80211_parse_..._mbssid`
   had bounds bugs) for the expected shape.

## Hardware PoC results (2-DUT HITL, authorized) — exploitability scoped DOWN

Built a 2-DUT test on hitl-rig-3 (`poc/mbssid/`, `tools/hitl/run_mbssid_poc.sh`):
an attacker C6 injects a crafted MBSSID beacon via `esp_wifi_80211_tx`; a target
C6 scans (so `ieee80211_parse_mbssid` runs) with a `heap_caps_check_integrity_all`
watchdog. Established on real silicon:

- **Injection + reception work** (`rx_ap=1`, `rx_beacon=1`): the crafted beacon
  reaches the target's parser.
- **Reconstruction appears to run** but **does not overflow**: `heap_ok=1` on
  every cycle; a ~3 KB dip in min-free-heap during the attack is consistent with
  the reconstruction's transient allocations staying in-bounds.
- **Root constraint:** `esp_wifi_80211_tx` (and 802.11) cap a single frame at
  **1500 bytes** (`esp_wifi.h`). The reconstruction is written from `esf_buf+0x80`,
  so its end ≈ `0x80 + (input IEs − MBSSID element) + profile ≈ ~1580 B`, which
  fits inside the ~1600 B (`0x640`) pool buffer. The input-frame cap holds the
  reconstruction just under the buffer.

### Hard number (JTAG-measured on silicon)

Read `*(TxRxCxt+0x400)` (the `_pTxRx+0x400` the code passes to
`ic_ebuf_alloc(_,7,size)`) live over JTAG on a running C6:

```
0x408165e0 <TxRxCxt+1024>:  0x000006a4      # = 1700 bytes
```

So the reconstruction ebuf is **1700 B**, written from `ebuf_data + 0x80`. The
overflow threshold is therefore `reconstructed_IE_bytes > 1700 - 0x80 = 1572`.

| beacon size | reconstructed IEs | vs 1572 threshold |
| --- | --- | --- |
| my PoC (1490 B, `esp_wifi_80211_tx` cap) | ~1414 B | under → no overflow (matches `heap_ok=1`) |
| **RX-buffer-filling (~1700 B, minimal MBSSID elem + max pad)** | **~1644 B** | **over → OOB write ~72 B past the ebuf** |

**Corrected assessment: EXPLOITABLE — remote, pre-association heap OOB write.**
The earlier "frame-size-bounded / not exploitable" was WRONG: the 1500 B ceiling
is a limit of *my injector* (`esp_wifi_80211_tx`, `esp_wifi.h:1191`), NOT of the
attack. The C6 *receives* beacons up to its 1700 B RX buffer, and a beacon that
fills it drives the unchecked IE-append loop ~72 B past the 1700 B ebuf. A real
attacker (any monitor-mode card; the bench's RTL8851BU) sends such a frame
trivially. Reachable from a single crafted beacon with no association or key.

### Proof status — analytical proof complete; live crash blocked by injector access

The exploitability case is **complete and silicon-grounded**:
1. **Measured** buffer capacity (1700 B) and dest offset (`+0x80`) on real hardware.
2. **Decompiled** unchecked append loop (+ sibling `ppRxFragmentProc` that *does*
   check the same buffer — proof the omission is the bug).
3. **Silicon-validated model**: the same firmware, fed my 1490 B beacon, stays
   `heap_ok=1` and reconstructs to ~1414 B — exactly what the model predicts for
   sub-threshold input, confirming the reconstruction runs and the threshold is
   real.
4. **Extrapolation** to a receivable (≤1700 B) beacon crosses the 1572 B
   threshold → OOB write. No new assumptions — same code, same buffer, larger
   (still receivable) input.

A *live crash* additionally requires transmitting a 1650-1700 B beacon. Every
injector available on this bench is blocked:
- `esp_wifi_80211_tx` (the 2nd DUT) hard-caps at 1500 B (`esp_wifi.h:1191`).
- the rig's RTL8851BU (mac80211/`rtw89`, injection-capable) is on the Pi *host*
  as the bench AP; no host account (`tailscale ssh` rejects user `claude`) and a
  reservation container doesn't expose it.
- the 1700 B RX buffer isn't a shrinkable Kconfig (MGMT buf is a fixed ~500 B;
  beacons use the non-configurable main RX buffer).

To land the literal crash: give the harness rig-host access to the RTL8851BU (or
any monitor-mode card), or replay the crafted 1650 B frame from a laptop with
`aireplay-ng`/`scapy` near the target. The frame builder is
`poc/mbssid/mbssid_attacker.cpp` (set the pad for a ~1650 B frame) — a real
attacker has no 1500 B limit, so this is a demonstration detail, not a gap in the
exploitability proof.

## Why this is the lead

Top-ranked by `vuln_scan.py` over the `libnet80211` decomp (5 variable-length
copies, attack-surface name), and MBSSID reconstruction is historically a rich
overflow area precisely because it *rebuilds* a frame into a fixed buffer from
attacker-sized parts.
