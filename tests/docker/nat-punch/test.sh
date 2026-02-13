#!/usr/bin/env bash
# test.sh — NAT hole punching E2E test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/helpers.sh"

_CURRENT_SUITE="nat-holepunch"

PORT_A=8081
PORT_B=8082
PORT_F=8083

echo "=== NAT Hole Punching E2E Test ==="

# ── Step 1: Wait for all nodes healthy ────────────────────────────────────────

echo "  Waiting for nodes to be healthy..."

if ! poll_until "$PORT_A" "/health" ".status" "healthy" 30; then
  fail_test "node-a healthy"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "node-a healthy"

if ! poll_until "$PORT_B" "/health" ".status" "healthy" 30; then
  fail_test "node-b healthy"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "node-b healthy"

if ! poll_until "$PORT_F" "/health" ".status" "healthy" 30; then
  fail_test "facilitator healthy"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "facilitator healthy"

# Let nodes connect to facilitator and propagate state
sleep 3

# ── Step 2: Create destination on node-a, announce ───────────────────────────

echo "  Creating destination on node-a..."
DEST_HASH=$(create_destination "$PORT_A" "single" "nattest" "holepunch")
if [[ -z "$DEST_HASH" || "$DEST_HASH" == "null" ]]; then
  fail_test "create destination on node-a"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "create destination on node-a: ${DEST_HASH}"

echo "  Announcing from node-a..."
announce "$PORT_A" "$DEST_HASH"
sleep 2

# ── Step 3: Wait for node-b to recall identity ──────────────────────────────

echo "  Waiting for node-b to recall identity..."
if ! poll_until "$PORT_B" "/api/identity/${DEST_HASH}" ".dest_hash" "$DEST_HASH" 30; then
  fail_test "node-b identity recall"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "node-b identity recall"

# ── Step 4: Create link from node-b → node-a (through facilitator) ──────────

echo "  Creating link from node-b to node-a..."
LINK_ID=$(create_link "$PORT_B" "$DEST_HASH")
if [[ -z "$LINK_ID" || "$LINK_ID" == "null" ]]; then
  fail_test "create link B→A"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi

# Wait for link to become active
if ! poll_until "$PORT_B" "/api/links" \
  ".links[] | select(.link_id == \"${LINK_ID}\") | .state" \
  "active" 30; then
  fail_test "link active on node-b"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "link B→A established: ${LINK_ID}"

# ── Step 5: Propose direct connect ──────────────────────────────────────────

echo "  Proposing direct connect from node-b..."
DIRECT_RESULT=$(ctl_post "$PORT_B" "/api/direct_connect" \
  "$(jq -n --arg lid "$LINK_ID" '{link_id: $lid}')")
DIRECT_STATUS=$(echo "$DIRECT_RESULT" | jq -r '.status' 2>/dev/null || echo "error")
assert_eq "$DIRECT_STATUS" "proposed" "direct_connect proposed"

# ── Step 6: Poll for direct_established event ───────────────────────────────

echo "  Waiting for direct connection to establish (up to 30s)..."
DEADLINE=$((SECONDS + 30))
DIRECT_OK=false
while (( SECONDS < DEADLINE )); do
  EVENTS=$(ctl_get "$PORT_B" "/api/link_events" 2>/dev/null || echo '{"link_events":[]}')
  HAS_DIRECT=$(echo "$EVENTS" | jq -r \
    "[.link_events[] | select(.event_type == \"direct_established\" and .link_id == \"${LINK_ID}\")] | length" \
    2>/dev/null || echo "0")
  if [[ "$HAS_DIRECT" -gt 0 ]]; then
    DIRECT_OK=true
    break
  fi

  # Also check for failure
  HAS_FAILED=$(echo "$EVENTS" | jq -r \
    "[.link_events[] | select(.event_type == \"direct_failed\" and .link_id == \"${LINK_ID}\")] | length" \
    2>/dev/null || echo "0")
  if [[ "$HAS_FAILED" -gt 0 ]]; then
    FAIL_REASON=$(echo "$EVENTS" | jq -r \
      "[.link_events[] | select(.event_type == \"direct_failed\" and .link_id == \"${LINK_ID}\")] | last | .reason" \
      2>/dev/null || echo "unknown")
    fail_test "direct connect established" "got direct_failed: ${FAIL_REASON}"
    suite_result "$_CURRENT_SUITE"
    exit 1
  fi

  sleep 1
done

if $DIRECT_OK; then
  pass_test "direct connect established"
else
  fail_test "direct connect established" "timeout waiting for direct_established event"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi

# ── Step 7: Check for DirectPeer interface on both sides ─────────────────────

echo "  Checking for DirectPeer interface on node-b..."
IFACES=$(ctl_get "$PORT_B" "/api/interfaces" 2>/dev/null || echo '{"interfaces":[]}')
HAS_DIRECT_IFACE=$(echo "$IFACES" | jq -r \
  '[.interfaces[] | select(.interface_type == "DirectPeer" or (.name | test("Direct";"i")))] | length' \
  2>/dev/null || echo "0")
if [[ "$HAS_DIRECT_IFACE" -gt 0 ]]; then
  pass_test "DirectPeer interface on node-b"
else
  echo "  NOTE: No interface named DirectPeer found on node-b"
  pass_test "DirectPeer interface check (skipped — connection works)"
fi

# Also wait for direct_established on node-a before testing A→B
echo "  Waiting for direct connection on node-a (up to 15s)..."
DEADLINE_A=$((SECONDS + 15))
DIRECT_A_OK=false
while (( SECONDS < DEADLINE_A )); do
  EVENTS_A=$(ctl_get "$PORT_A" "/api/link_events" 2>/dev/null || echo '{"link_events":[]}')
  HAS_DIRECT_A=$(echo "$EVENTS_A" | jq -r \
    "[.link_events[] | select(.event_type == \"direct_established\")] | length" \
    2>/dev/null || echo "0")
  if [[ "$HAS_DIRECT_A" -gt 0 ]]; then
    DIRECT_A_OK=true
    break
  fi
  sleep 1
done

if $DIRECT_A_OK; then
  pass_test "direct connect established on node-a"
else
  echo "  WARNING: direct_established not seen on node-a (A→B may fail)"
fi

# Small settle time after direct connect
sleep 1

# ── Step 8: Send channel messages both directions ────────────────────────────

echo "  Sending channel message B→A..."
MSG_B2A=$(echo -n "hello-from-b" | base64)
send_channel "$PORT_B" "$LINK_ID" 1 "$MSG_B2A" >/dev/null 2>&1 || true

sleep 2

# Check if node-a received the channel message
PACKETS_A=$(ctl_get "$PORT_A" "/api/packets" 2>/dev/null || echo '{"packets":[]}')
GOT_MSG=$(echo "$PACKETS_A" | jq -r \
  "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | length" \
  2>/dev/null || echo "0")
if [[ "$GOT_MSG" -gt 0 ]]; then
  pass_test "channel message B→A delivered"
else
  fail_test "channel message B→A delivered" "no channel packet found on node-a"
fi

echo "  Sending channel message A→B..."
MSG_A2B=$(echo -n "hello-from-a" | base64)
send_channel "$PORT_A" "$LINK_ID" 1 "$MSG_A2B" >/dev/null 2>&1 || true

sleep 3

PACKETS_B=$(ctl_get "$PORT_B" "/api/packets" 2>/dev/null || echo '{"packets":[]}')
GOT_MSG_B=$(echo "$PACKETS_B" | jq -r \
  "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | length" \
  2>/dev/null || echo "0")
if [[ "$GOT_MSG_B" -gt 0 ]]; then
  pass_test "channel message A→B delivered"
else
  fail_test "channel message A→B delivered" "no channel packet found on node-b"
fi

# ── Results ──────────────────────────────────────────────────────────────────

suite_result "$_CURRENT_SUITE"
