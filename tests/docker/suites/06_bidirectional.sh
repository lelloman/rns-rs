#!/usr/bin/env bash
# Suite 06: Bidirectional — A and B send to each other simultaneously
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="06_bidirectional"
echo "Suite 06: Bidirectional messaging"

if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  skip_suite "Bidirectional test requires chain or mesh topology"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"

# Both nodes create inbound destinations and announce
DEST_A=$(create_destination "$PORT_A" "single" "testbidir" "ab" "all")
DEST_B=$(create_destination "$PORT_B" "single" "testbidir" "ba" "all")
echo "  Node-a dest: ${DEST_A}"
echo "  Node-b dest: ${DEST_B}"

announce "$PORT_A" "$DEST_A"
announce "$PORT_B" "$DEST_B"
echo "  Both announced"

# Wait for identity recalls
echo "  Waiting for identity recalls..."
if ! poll_until "$PORT_B" "/api/identity/${DEST_A}" ".dest_hash" "$DEST_A" 30; then
  fail_test "Node-b cannot recall node-a identity"
  suite_result "06_bidirectional"
  exit 0
fi

if ! poll_until "$PORT_A" "/api/identity/${DEST_B}" ".dest_hash" "$DEST_B" 30; then
  fail_test "Node-a cannot recall node-b identity"
  suite_result "06_bidirectional"
  exit 0
fi
echo "  Both identities recalled"

# Create outbound destinations
OUT_B_TO_A=$(create_outbound_dest "$PORT_B" "testbidir" "ab" "$DEST_A")
OUT_A_TO_B=$(create_outbound_dest "$PORT_A" "testbidir" "ba" "$DEST_B")

# Send messages in both directions
DATA_A_TO_B="bXNnIGEtPmI="  # "msg a->b"
DATA_B_TO_A="bXNnIGItPmE="  # "msg b->a"

SEND_A=$(send_packet "$PORT_A" "$OUT_A_TO_B" "$DATA_A_TO_B")
SEND_B=$(send_packet "$PORT_B" "$OUT_B_TO_A" "$DATA_B_TO_A")
HASH_A=$(echo "$SEND_A" | jq -r '.packet_hash')
HASH_B=$(echo "$SEND_B" | jq -r '.packet_hash')
echo "  A->B packet: ${HASH_A}"
echo "  B->A packet: ${HASH_B}"

# Verify B receives A's packet
echo "  Waiting for A->B delivery..."
if poll_until "$PORT_B" "/api/packets" \
  ".packets[] | select(.packet_hash == \"${HASH_A}\") | .packet_hash" \
  "$HASH_A" 30; then
  pass_test "B received A's packet"
else
  fail_test "B did not receive A's packet"
fi

# Verify A receives B's packet
echo "  Waiting for B->A delivery..."
if poll_until "$PORT_A" "/api/packets" \
  ".packets[] | select(.packet_hash == \"${HASH_B}\") | .packet_hash" \
  "$HASH_B" 30; then
  pass_test "A received B's packet"
else
  fail_test "A did not receive B's packet"
fi

suite_result "06_bidirectional"
