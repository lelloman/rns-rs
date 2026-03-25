#!/usr/bin/env bash
# Suite 20: Sentinel behavioral blacklist
#
# Requires backbone interfaces (RNS_BACKBONE=1 during topology generation).
# Tests:
#   1. Start rns-sentineld against the local provider bridge
#   2. Sentinel blacklists a backbone peer after repeated idle-timeout telemetry
#   3. Reconnect attempts are rejected while the blacklist is active
#   4. Peer reconnects after the blacklist expires
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="20_sentinel_blacklist"
echo "Suite 20: Sentinel behavioral blacklist"

if [[ "${RNS_BACKBONE:-0}" != "1" ]]; then
  skip_suite "requires RNS_BACKBONE=1 topology"
fi

if (( TOPO_N < 2 )); then
  skip_suite "requires chain of >= 2 nodes"
fi

PORT_A="${NODE_A_PORT}"
SERVER_CONTAINER="node-a"

start_sentinel() {
  local container="$1"
  docker exec "$container" sh -lc '
    pkill -f "/usr/local/bin/rns-sentineld" >/dev/null 2>&1 || true
    nohup /usr/local/bin/rns-sentineld \
      --config /data \
      --socket /data/provider.sock \
      --idle-timeout-threshold 1 \
      --idle-timeout-window 30 \
      --base-blacklist 15 \
      --flap-threshold 0 \
      --connect-rate-threshold 0 \
      >/tmp/rns-sentineld.log 2>&1 &
  '
}

peer_field() {
  local ip="$1"
  local field="$2"
  curl -sf "http://localhost:${PORT_A}/api/backbone/peers" \
    | jq -r ".peers[] | select(.ip == \"${ip}\") | .${field}"
}

start_sentinel "$SERVER_CONTAINER"
sleep 3
pass_test "started rns-sentineld in ${SERVER_CONTAINER}"

if poll_count "$PORT_A" "/api/backbone/peers" ".peers" 1 30; then
  pass_test "backbone peer state has at least 1 peer"
else
  fail_test "backbone peer state has at least 1 peer" "no peers found within 30s"
  suite_result "20_sentinel_blacklist"
  exit 0
fi

PEER_IP=$(curl -sf "http://localhost:${PORT_A}/api/backbone/peers" | jq -r '.peers[0].ip')
PEER_INTERFACE=$(curl -sf "http://localhost:${PORT_A}/api/backbone/peers" | jq -r '.peers[0].interface')

assert_ne "$PEER_IP" "null" "peer IP is not null"
assert_ne "$PEER_INTERFACE" "null" "peer interface is not null"

echo "  Observing peer: ${PEER_IP} on interface ${PEER_INTERFACE}"

if poll_until "$PORT_A" "/api/backbone/peers" \
  ".peers[] | select(.ip == \"${PEER_IP}\") | .blacklist_reason // \"\"" \
  "repeated idle timeouts" 40; then
  pass_test "sentinel blacklists peer after idle timeout telemetry"
else
  fail_test "sentinel blacklists peer after idle timeout telemetry" \
    "peer never reached blacklist reason 'repeated idle timeouts'"
  echo "--- ${SERVER_CONTAINER} sentinel log ---"
  docker exec "$SERVER_CONTAINER" sh -lc 'cat /tmp/rns-sentineld.log || true'
  echo "--- end sentinel log ---"
  suite_result "20_sentinel_blacklist"
  exit 0
fi

BLACKLIST_REMAINING=$(peer_field "$PEER_IP" "blacklisted_remaining_secs // 0")
if [[ -n "$BLACKLIST_REMAINING" ]] && (( $(echo "$BLACKLIST_REMAINING > 0" | bc -l 2>/dev/null || echo 0) )); then
  pass_test "peer ${PEER_IP} shows active blacklist"
else
  fail_test "peer ${PEER_IP} shows active blacklist" "remaining_secs=${BLACKLIST_REMAINING:-null}"
fi

REJECT_BEFORE=$(peer_field "$PEER_IP" "reject_count // 0")
sleep 5
REJECT_AFTER=$(peer_field "$PEER_IP" "reject_count // 0")
if (( REJECT_AFTER > REJECT_BEFORE )); then
  pass_test "blacklisted peer reconnect attempts are rejected (${REJECT_BEFORE} -> ${REJECT_AFTER})"
else
  fail_test "blacklisted peer reconnect attempts are rejected" \
    "reject_count did not increase: ${REJECT_BEFORE} -> ${REJECT_AFTER}"
fi

if poll_until "$PORT_A" "/api/backbone/peers" \
  ".peers[] | select(.ip == \"${PEER_IP}\") | (.blacklisted_remaining_secs // 0 | floor)" \
  "0" 20; then
  pass_test "blacklist expires for peer ${PEER_IP}"
else
  fail_test "blacklist expires for peer ${PEER_IP}" "peer stayed blacklisted for longer than expected"
fi

if poll_until "$PORT_A" "/api/backbone/peers" \
  ".peers[] | select(.ip == \"${PEER_IP}\") | .connected_count" \
  "1" 20; then
  pass_test "peer ${PEER_IP} reconnects after blacklist expiry"
else
  fail_test "peer ${PEER_IP} reconnects after blacklist expiry" "connected_count did not return to 1"
fi

suite_result "20_sentinel_blacklist"
