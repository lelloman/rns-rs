#!/usr/bin/env bash
# Suite 19: Burst Packets — rapid packet sending stress test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="19_burst_packets"
echo "Suite 19: Burst packets stress test"

if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  skip_suite "Burst packets test requires chain or mesh topology"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"

BURST_COUNT=50

# Node-A creates inbound destination with proof_strategy=all, announces
DEST_A=$(create_destination "$PORT_A" "single" "testburst" "stress" "all")
echo "  Node-A destination: ${DEST_A}"
announce "$PORT_A" "$DEST_A"
echo "  Node-A announced"

# Wait for Node-B to recall identity
echo "  Waiting for identity recall on Node-B..."
if ! poll_until "$PORT_B" "/api/identity/${DEST_A}" ".dest_hash" "$DEST_A" 30; then
  fail_test "Identity not recalled on Node-B"
  suite_result "19_burst_packets"
  exit 0
fi
echo "  Identity recalled"

# Node-B creates outbound dest
DEST_B_OUT=$(create_outbound_dest "$PORT_B" "testburst" "stress" "$DEST_A")
echo "  Node-B outbound dest: ${DEST_B_OUT}"

# Send 50 packets rapidly (no sleep between sends)
echo "  Sending ${BURST_COUNT} packets rapidly..."
for (( i=1; i<=BURST_COUNT; i++ )); do
  data_b64=$(echo -n "burst-packet-${i}" | base64)
  send_packet "$PORT_B" "$DEST_B_OUT" "$data_b64" > /dev/null 2>&1 || true
done
echo "  All ${BURST_COUNT} packets sent"

# Poll Node-A until all packets received (timeout 60s)
echo "  Waiting for ${BURST_COUNT} packets on Node-A..."
if poll_count "$PORT_A" "/api/packets" ".packets" "$BURST_COUNT" 60; then
  recv_count=$(get_packets "$PORT_A" | jq '.packets | length')
  assert_ge "$recv_count" "$BURST_COUNT" "Node-A received >= ${BURST_COUNT} packets"
else
  recv_count=$(get_packets "$PORT_A" | jq '.packets | length')
  fail_test "Node-A received only ${recv_count}/${BURST_COUNT} packets"
fi

# Poll Node-B for proofs (timeout 60s)
echo "  Waiting for ${BURST_COUNT} proofs on Node-B..."
if poll_count "$PORT_B" "/api/proofs" ".proofs" "$BURST_COUNT" 60; then
  proof_count=$(get_proofs "$PORT_B" | jq '.proofs | length')
  assert_ge "$proof_count" "$BURST_COUNT" "Node-B received >= ${BURST_COUNT} proofs"
else
  proof_count=$(get_proofs "$PORT_B" | jq '.proofs | length')
  fail_test "Node-B received only ${proof_count}/${BURST_COUNT} proofs"
fi

suite_result "19_burst_packets"
