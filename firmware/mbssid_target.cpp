// mbssid_target — HITL security-test TARGET firmware (finding 001).
//
// Authorized security testing (isolated HITL bench, own hardware). Runs the
// stock ESP32-C6 WiFi stack in station+scan mode so that beacons received from
// the paired "attacker" DUT are parsed by ieee80211_parse_mbssid() in the closed
// libnet80211 blob — the function audited in
// esp32-reverse/docs/audit/findings/001-mbssid-reconstruction.md.
//
// It continuously scans and, every cycle, checks full heap integrity and prints
// free/min-free heap over USB-CDC (the serial `hitl monitor` reads). A crafted
// MBSSID beacon that overflows the reconstruction esf_buf will manifest as:
//   * heap_ok=0 (heap_caps_check_integrity_all trips on the corrupted canary), or
//   * an outright panic/abort (dumped to serial; the core halts for the attached
//     JTAG/GDB session), or
//   * a min-free-heap cliff / assert.
//
// Baseline (benign attacker beacon) should hold heap_ok=1 indefinitely.

#include <WiFi.h>

#include "esp_heap_caps.h"
#include "esp_wifi.h"

static uint32_t g_cycle = 0;

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("mbssid-target: boot");
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true, true);
  delay(100);
  Serial.println("mbssid-target: scanning (parses received beacons incl. MBSSID)");
}

void loop() {
  // Channel-6-locked passive scan with a long dwell: the injector TXes the
  // crafted MBSSID beacon on channel 6, so parking here maximizes how many
  // crafted beacons ieee80211_parse_mbssid() processes per cycle (the all-channel
  // hop only dwelt ~120 ms on ch6). Passive => we just listen and parse beacons.
  int n = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/true,
                            /*passive=*/true, /*max_ms_per_chan=*/700,
                            /*channel=*/6);

  size_t freeheap = esp_get_free_heap_size();
  size_t minheap = esp_get_minimum_free_heap_size();
  // true => print the first corrupt block if any (goes to serial before we do).
  bool heap_ok = heap_caps_check_integrity_all(true);

  // Did we receive the attacker's beacon (SEC-MBSSID) and did MBSSID
  // reconstruction synthesize the nontransmitted BSSID (ntx)? Seeing either
  // proves the beacon reached the parser; `ntx` proves ieee80211_parse_mbssid
  // ran the reconstruction path we're attacking.
  int saw_tx = 0, saw_ntx = 0, saw_ap = 0;
  for (int i = 0; i < n; i++) {
    String s = WiFi.SSID(i);
    if (s.startsWith("SEC-MBSSID")) saw_tx = 1;
    if (s == "ntx") saw_ntx = 1;
    if (s == "SEC-AP-REACH") saw_ap = 1;  // real SoftAP => RF reachability OK
  }

  Serial.printf("mbssid-target: cycle=%lu scan=%d free=%u min=%u heap_ok=%d rx_ap=%d rx_beacon=%d rx_ntx=%d\n",
                (unsigned long)g_cycle++, n, (unsigned)freeheap,
                (unsigned)minheap, heap_ok ? 1 : 0, saw_ap, saw_tx, saw_ntx);

  if (!heap_ok) {
    // Latch the failure loudly; the harness greps for this line.
    Serial.println("mbssid-target: HEAP CORRUPTION DETECTED (finding 001 triggered)");
  }

  if (n >= 0) {
    WiFi.scanDelete();
  }
  delay(150);
}
