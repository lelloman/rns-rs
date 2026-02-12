#!/usr/bin/env bash
# Suite 04: Packet Delivery — encrypted message delivery via chain
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="04_packet_delivery"
echo "Suite 04: Packet delivery"

if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  skip_suite "Packet delivery test requires chain or mesh topology"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"

# Node-a: create inbound single dest with proof_strategy=all, announce
DEST_A=$(create_destination "$PORT_A" "single" "testpacket" "delivery" "all")
echo "  Node-a destination: ${DEST_A}"
announce "$PORT_A" "$DEST_A"
echo "  Node-a announced"

# Wait for node-b to learn about node-a's identity via announce
echo "  Waiting for node-b to recall identity..."
if poll_until "$PORT_B" "/api/identity/${DEST_A}" ".dest_hash" "$DEST_A" 30; then
  echo "  Identity recalled on node-b"
else
  fail_test "Identity not recalled on node-b"
  suite_result "04_packet_delivery"
  exit 0
fi

# Node-b: create outbound dest targeting node-a, send packet
DEST_B_OUT=$(create_outbound_dest "$PORT_B" "testpacket" "delivery" "$DEST_A")
echo "  Node-b outbound dest: ${DEST_B_OUT}"

# Send a test message
TEST_DATA="aGVsbG8gd29ybGQ="  # "hello world" in base64
SEND_RESULT=$(send_packet "$PORT_B" "$DEST_B_OUT" "$TEST_DATA")
PACKET_HASH=$(echo "$SEND_RESULT" | jq -r '.packet_hash')
echo "  Sent packet: ${PACKET_HASH}"

# Poll node-a for packet delivery
echo "  Waiting for packet on node-a..."
if poll_until "$PORT_A" "/api/packets" \
  ".packets[] | select(.packet_hash == \"${PACKET_HASH}\") | .packet_hash" \
  "$PACKET_HASH" 30; then

  # Verify packet arrived at the correct destination
  recv_dest=$(get_packets "$PORT_A" | jq -r ".packets[] | select(.packet_hash == \"${PACKET_HASH}\") | .dest_hash")
  assert_eq "$recv_dest" "$DEST_A" "Packet delivered to correct destination"
else
  fail_test "Packet not delivered to node-a"
fi

suite_result "04_packet_delivery"
