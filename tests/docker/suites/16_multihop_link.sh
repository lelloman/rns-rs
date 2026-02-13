#!/usr/bin/env bash
# Suite 16: Multi-hop Link — link through intermediate transport nodes
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="16_multihop_link"
echo "Suite 16: Multi-hop link"

if [[ "${TOPO_TYPE:-chain}" != "chain" ]]; then
  skip_suite "Multi-hop link test requires chain topology"
fi

N="${TOPO_N:-5}"
if (( N < 3 )); then
  skip_suite "Need chain-3 or longer for multi-hop link test"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"

# Determine last node port
last_idx=$(( N - 1 ))
last_letter=$(printf "\\$(printf '%03o' "$(( last_idx + 97 ))")")
last_varname="NODE_$(echo "$last_letter" | tr '[:lower:]' '[:upper:]')_PORT"
PORT_LAST="${!last_varname}"
echo "  First node: port ${PORT_A}, Last node: port ${PORT_LAST} (node-${last_letter})"

# Node-A creates inbound destination and announces
DEST_A=$(create_destination "$PORT_A" "single" "testmhlink" "hop")
echo "  Node-A destination: ${DEST_A}"
announce "$PORT_A" "$DEST_A"
echo "  Node-A announced"

# Wait for announce to reach the last node
echo "  Waiting for last node to recall identity..."
if ! poll_until "$PORT_LAST" "/api/identity/${DEST_A}" ".dest_hash" "$DEST_A" 60; then
  fail_test "Identity not recalled on last node"
  suite_result "16_multihop_link"
  exit 0
fi
echo "  Identity recalled on last node"

# Last node creates link to Node-A
echo "  Last node creating link to Node-A..."
LINK_ID=$(create_link "$PORT_LAST" "$DEST_A")
echo "  Link: ${LINK_ID}"

if [[ -z "$LINK_ID" || "$LINK_ID" == "null" ]]; then
  fail_test "create_link returned empty or null"
  suite_result "16_multihop_link"
  exit 0
fi

# Wait for link to become active on both ends
echo "  Waiting for link active on last node..."
if poll_until "$PORT_LAST" "/api/links" \
  ".links[] | select(.link_id == \"${LINK_ID}\") | .state" \
  "active" 60; then
  pass_test "Link active on last node"
else
  fail_test "Link not active on last node"
  suite_result "16_multihop_link"
  exit 0
fi

echo "  Waiting for link active on Node-A..."
if poll_until "$PORT_A" "/api/links" \
  ".links[] | select(.link_id == \"${LINK_ID}\") | .state" \
  "active" 60; then
  pass_test "Link active on Node-A"
else
  fail_test "Link not active on Node-A"
fi

# Send channel message from last node to Node-A
PAYLOAD_B64=$(echo -n "multihop-channel-test" | base64)
echo "  Last node sending channel message..."
send_channel "$PORT_LAST" "$LINK_ID" 77 "$PAYLOAD_B64"

# Verify delivery on Node-A
echo "  Waiting for channel message on Node-A..."
if poll_until "$PORT_A" "/api/packets" \
  "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | length | . > 0" \
  "true" 30; then

  recv_data=$(get_packets "$PORT_A" | jq -r \
    "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | last | .data_base64")
  assert_eq "$recv_data" "$PAYLOAD_B64" "Multi-hop channel payload matches"
else
  fail_test "Multi-hop channel message not received on Node-A"
fi

# Verify link RTT > 0 (should be higher than direct due to hops)
rtt=$(get_links "$PORT_LAST" | jq -r ".links[] | select(.link_id == \"${LINK_ID}\") | .rtt")
if [[ -n "$rtt" && "$rtt" != "null" ]]; then
  rtt_positive=$(echo "$rtt" | awk '{print ($1 > 0) ? "yes" : "no"}')
  assert_eq "$rtt_positive" "yes" "Multi-hop link RTT > 0"
else
  fail_test "Multi-hop link RTT is null or empty"
fi

suite_result "16_multihop_link"
