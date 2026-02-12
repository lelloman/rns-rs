#!/usr/bin/env bash
# Suite 12: Mesh Routing — multi-path routing in fully-connected mesh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="12_mesh_routing"
echo "Suite 12: Mesh routing"

if [[ "${TOPO_TYPE:-chain}" != "mesh" ]]; then
  skip_suite "Mesh routing test requires mesh topology"
fi

N="${TOPO_N:-4}"
if (( N < 3 )); then
  skip_suite "Need mesh-3 or larger"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"

# Node-a creates destination and announces
DEST_A=$(create_destination "$PORT_A" "single" "testmesh" "routing" "all")
echo "  Node-a dest: ${DEST_A}"
announce "$PORT_A" "$DEST_A"
echo "  Node-a announced"

# All other nodes should receive announce with hops=1 (directly connected)
for (( i=1; i<N; i++ )); do
  node_letter=$(printf "\\$(printf '%03o' "$(( i + 97 ))")")
  varname="NODE_$(echo "$node_letter" | tr '[:lower:]' '[:upper:]')_PORT"
  port="${!varname}"

  echo "  Checking node-${node_letter}..."
  if poll_until "$port" "/api/announces" \
    ".announces[] | select(.dest_hash == \"${DEST_A}\") | .dest_hash" \
    "$DEST_A" 30; then

    hops=$(get_announces "$port" | jq -r ".announces[] | select(.dest_hash == \"${DEST_A}\") | .hops")
    assert_eq "$hops" "1" "node-${node_letter} received with hops=1"
  else
    fail_test "node-${node_letter} did not receive announce"
  fi
done

# Send packet from last node to node-a
last_idx=$(( N - 1 ))
last_letter=$(printf "\\$(printf '%03o' "$(( last_idx + 97 ))")")
last_varname="NODE_$(echo "$last_letter" | tr '[:lower:]' '[:upper:]')_PORT"
last_port="${!last_varname}"

echo "  Sending packet from node-${last_letter} to node-a..."

# Wait for identity recall
if ! poll_until "$last_port" "/api/identity/${DEST_A}" ".dest_hash" "$DEST_A" 30; then
  fail_test "node-${last_letter} cannot recall node-a identity"
  suite_result "12_mesh_routing"
  exit 0
fi

# Create outbound dest and send
OUT_DEST=$(create_outbound_dest "$last_port" "testmesh" "routing" "$DEST_A")
TEST_DATA=$(echo -n "mesh routing test" | base64)
SEND_RESULT=$(send_packet "$last_port" "$OUT_DEST" "$TEST_DATA")
PKT_HASH=$(echo "$SEND_RESULT" | jq -r '.packet_hash')
echo "  Sent packet: ${PKT_HASH}"

# Verify delivery on node-a
if poll_until "$PORT_A" "/api/packets" \
  ".packets[] | select(.packet_hash == \"${PKT_HASH}\") | .packet_hash" \
  "$PKT_HASH" 30; then
  pass_test "Packet delivered via mesh"
else
  fail_test "Packet not delivered"
fi

suite_result "12_mesh_routing"
