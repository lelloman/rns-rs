#!/usr/bin/env bash
# Suite 20: Sentinel blacklist — verify backbone peer blacklisting via HTTP API
#
# Requires backbone interfaces (RNS_BACKBONE=1 during topology generation).
# Tests:
#   1. Backbone peer state API returns connected peers
#   2. Blacklisting a peer via API succeeds
#   3. Blacklisted peer appears in peer state with remaining seconds
#   4. Blacklisted peer is rejected on reconnect (connection count doesn't increase)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="20_sentinel_blacklist"
echo "Suite 20: Sentinel blacklist (backbone peer state)"

# This suite only works with backbone interfaces
if [[ "${RNS_BACKBONE:-0}" != "1" ]]; then
  skip_suite "requires RNS_BACKBONE=1 topology"
fi

# Need at least 2 nodes in the chain
if (( TOPO_N < 2 )); then
  skip_suite "requires chain of >= 2 nodes"
fi

# Use the first node (node-a) as the backbone server
PORT_A="${NODE_A_PORT}"

# ── Test 1: Peer state API returns entries ──────────────────────────────────

# Wait for at least one backbone peer to connect (node-b connects to node-a)
if poll_count "$PORT_A" "/api/backbone/peers" ".peers" 1 30; then
  pass_test "backbone peer state has at least 1 peer"
else
  fail_test "backbone peer state has at least 1 peer" "no peers found within 30s"
  suite_result "20_sentinel_blacklist"
  exit 0
fi

# Get the connected peer's IP
PEER_IP=$(curl -sf "http://localhost:${PORT_A}/api/backbone/peers" | jq -r '.peers[0].ip')
PEER_INTERFACE=$(curl -sf "http://localhost:${PORT_A}/api/backbone/peers" | jq -r '.peers[0].interface')

assert_ne "$PEER_IP" "null" "peer IP is not null"
assert_ne "$PEER_INTERFACE" "null" "peer interface is not null"

echo "  Found peer: ${PEER_IP} on interface ${PEER_INTERFACE}"

# ── Test 2: Blacklist the peer via API ──────────────────────────────────────

BLACKLIST_RESULT=$(curl -sf -X POST -H "Content-Type: application/json" \
  -d "{\"interface\": \"${PEER_INTERFACE}\", \"ip\": \"${PEER_IP}\", \"duration_secs\": 60}" \
  "http://localhost:${PORT_A}/api/backbone/blacklist" | jq -r '.status')

assert_eq "$BLACKLIST_RESULT" "ok" "blacklist API returns ok"

# ── Test 3: Peer shows as blacklisted ──────────────────────────────────────

sleep 1
BLACKLIST_REMAINING=$(curl -sf "http://localhost:${PORT_A}/api/backbone/peers" \
  | jq -r ".peers[] | select(.ip == \"${PEER_IP}\") | .blacklisted_remaining_secs // 0")

if [[ -n "$BLACKLIST_REMAINING" ]] && (( $(echo "$BLACKLIST_REMAINING > 0" | bc -l 2>/dev/null || echo 0) )); then
  pass_test "peer ${PEER_IP} shows blacklisted with remaining seconds"
else
  fail_test "peer ${PEER_IP} shows blacklisted" "remaining_secs=${BLACKLIST_REMAINING:-null}"
fi

BLACKLIST_REASON=$(curl -sf "http://localhost:${PORT_A}/api/backbone/peers" \
  | jq -r ".peers[] | select(.ip == \"${PEER_IP}\") | .blacklist_reason // \"none\"")
assert_eq "$BLACKLIST_REASON" "sentinel blacklist" "blacklist reason is 'sentinel blacklist'"

# ── Test 4: Blacklisted peer's reconnection attempts are rejected ──────────

# Record the current reject count
REJECT_BEFORE=$(curl -sf "http://localhost:${PORT_A}/api/backbone/peers" \
  | jq -r ".peers[] | select(.ip == \"${PEER_IP}\") | .reject_count // 0")

# Wait a few seconds for the backbone client (node-b) to attempt reconnection
# (backbone clients reconnect automatically after disconnect)
sleep 5

REJECT_AFTER=$(curl -sf "http://localhost:${PORT_A}/api/backbone/peers" \
  | jq -r ".peers[] | select(.ip == \"${PEER_IP}\") | .reject_count // 0")

if (( REJECT_AFTER > REJECT_BEFORE )); then
  pass_test "blacklisted peer reconnection attempts rejected (rejects: ${REJECT_BEFORE} -> ${REJECT_AFTER})"
else
  fail_test "blacklisted peer reconnection attempts rejected" "reject_count did not increase: ${REJECT_BEFORE} -> ${REJECT_AFTER}"
fi

suite_result "20_sentinel_blacklist"
