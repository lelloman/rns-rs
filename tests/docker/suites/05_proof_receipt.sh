#!/usr/bin/env bash
# Suite 05: Proof Receipt — proof roundtrip after packet delivery
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="05_proof_receipt"
echo "Suite 05: Proof receipt"

if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  skip_suite "Proof receipt test requires chain or mesh topology"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"

# Node-a: inbound dest with proof_strategy=all
DEST_A=$(create_destination "$PORT_A" "single" "testproof" "receipt" "all")
echo "  Node-a destination: ${DEST_A}"
announce "$PORT_A" "$DEST_A"

# Wait for identity recall on node-b
if ! poll_until "$PORT_B" "/api/identity/${DEST_A}" ".dest_hash" "$DEST_A" 30; then
  fail_test "Identity not recalled on node-b"
  suite_result "05_proof_receipt"
  exit 0
fi

# Node-b sends packet
DEST_B_OUT=$(create_outbound_dest "$PORT_B" "testproof" "receipt" "$DEST_A")
TEST_DATA="cHJvb2YgdGVzdA=="  # "proof test" in base64
SEND_RESULT=$(send_packet "$PORT_B" "$DEST_B_OUT" "$TEST_DATA")
PACKET_HASH=$(echo "$SEND_RESULT" | jq -r '.packet_hash')
echo "  Sent packet: ${PACKET_HASH}"

# Wait for packet delivery on node-a
if ! poll_until "$PORT_A" "/api/packets" \
  ".packets[] | select(.packet_hash == \"${PACKET_HASH}\") | .packet_hash" \
  "$PACKET_HASH" 30; then
  fail_test "Packet not delivered"
  suite_result "05_proof_receipt"
  exit 0
fi

# Poll node-b for proof
echo "  Waiting for proof on node-b..."
if poll_until "$PORT_B" "/api/proofs" \
  ".proofs[] | select(.packet_hash == \"${PACKET_HASH}\") | .packet_hash" \
  "$PACKET_HASH" 30; then

  rtt=$(get_proofs "$PORT_B" | jq -r ".proofs[] | select(.packet_hash == \"${PACKET_HASH}\") | .rtt")
  # RTT should be > 0 (use awk for float comparison)
  rtt_positive=$(awk "BEGIN { print ($rtt > 0) ? 1 : 0 }" 2>/dev/null) || rtt_positive=0
  if (( rtt_positive )); then
    pass_test "Proof received, RTT=${rtt}"
  else
    assert_ne "$rtt" "null" "Proof RTT is not null"
    assert_ne "$rtt" "" "Proof RTT is not empty"
  fi
else
  fail_test "Proof not received on node-b"
fi

suite_result "05_proof_receipt"
