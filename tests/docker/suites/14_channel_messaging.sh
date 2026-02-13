#!/usr/bin/env bash
# Suite 14: Channel Messaging — channel messages over links
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="14_channel_messaging"
echo "Suite 14: Channel messaging"

if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  skip_suite "Channel messaging test requires chain or mesh topology"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"

# Establish link: Node-B (initiator) → Node-A (listener)
echo "  Establishing link B → A..."
LINK_RESULT=$(establish_link "$PORT_B" "$PORT_A" "testchannel" "msg") || true
LINK_ID=$(echo "$LINK_RESULT" | awk '{print $1}')
DEST_A=$(echo "$LINK_RESULT" | awk '{print $2}')
echo "  Link: ${LINK_ID}, Dest: ${DEST_A}"

if [[ -z "$LINK_ID" || "$LINK_ID" == "null" ]]; then
  fail_test "Failed to establish link"
  suite_result "14_channel_messaging"
  exit 0
fi

# Node-B sends channel message (msgtype=42, payload="hello channel")
PAYLOAD_B64=$(echo -n "hello channel" | base64)
echo "  Node-B sending channel message (msgtype=42)..."
send_channel "$PORT_B" "$LINK_ID" 42 "$PAYLOAD_B64"

# Poll Node-A's packets for channel message
echo "  Waiting for channel message on Node-A..."
if poll_until "$PORT_A" "/api/packets" \
  "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | length | . > 0" \
  "true" 30; then

  # Verify payload matches
  recv_data=$(get_packets "$PORT_A" | jq -r \
    "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | last | .data_base64")
  assert_eq "$recv_data" "$PAYLOAD_B64" "Channel payload matches on Node-A"

  # Verify msgtype is embedded in dest_hash
  recv_dest=$(get_packets "$PORT_A" | jq -r \
    "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | last | .dest_hash")
  echo "  Channel dest_hash: ${recv_dest}"
  # dest_hash format: "channel:{link_id}:{msgtype}"
  recv_msgtype=$(echo "$recv_dest" | awk -F: '{print $NF}')
  assert_eq "$recv_msgtype" "42" "Channel msgtype matches"
else
  fail_test "Channel message not received on Node-A"
fi

# Now test reverse direction: Node-A sends channel message to Node-B
# Node-A needs to use the same link_id (it's the same link, seen from both sides)
PAYLOAD_REV_B64=$(echo -n "hello back" | base64)
echo "  Node-A sending channel message back (msgtype=99)..."
send_channel "$PORT_A" "$LINK_ID" 99 "$PAYLOAD_REV_B64"

echo "  Waiting for reverse channel message on Node-B..."
if poll_until "$PORT_B" "/api/packets" \
  "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | length | . > 0" \
  "true" 30; then

  recv_data_rev=$(get_packets "$PORT_B" | jq -r \
    "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | last | .data_base64")
  assert_eq "$recv_data_rev" "$PAYLOAD_REV_B64" "Reverse channel payload matches on Node-B"
else
  fail_test "Reverse channel message not received on Node-B"
fi

suite_result "14_channel_messaging"
