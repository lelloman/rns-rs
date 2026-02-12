#!/usr/bin/env bash
# Suite 03: Multi-hop Announce — announce propagation across chain
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="03_announce_multihop"
echo "Suite 03: Multi-hop announce"

if [[ "${TOPO_TYPE:-chain}" != "chain" ]]; then
  skip_suite "Multi-hop announce test requires chain topology"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"

# Determine chain length from topology
N="${TOPO_N:-5}"
if (( N < 3 )); then
  skip_suite "Need chain-3 or longer for multi-hop test"
fi

# Node-a creates and announces
DEST_HASH=$(create_destination "$PORT_A" "single" "testmultihop" "announce")
echo "  Created destination on node-a: ${DEST_HASH}"
announce "$PORT_A" "$DEST_HASH"
echo "  Announced from node-a"

# Check each node in the chain for the announce with correct hop count
last_idx=$(( N - 1 ))
for (( i=1; i<=last_idx; i++ )); do
  node_letter=$(printf "\\$(printf '%03o' "$(( i + 97 ))")")
  varname="NODE_$(echo "$node_letter" | tr '[:lower:]' '[:upper:]')_PORT"
  port="${!varname}"

  echo "  Polling node-${node_letter} (port ${port}) for announce..."
  if poll_until "$port" "/api/announces" \
    ".announces[] | select(.dest_hash == \"${DEST_HASH}\") | .dest_hash" \
    "$DEST_HASH" 60; then

    hops=$(get_announces "$port" | jq -r ".announces[] | select(.dest_hash == \"${DEST_HASH}\") | .hops")
    assert_ge "$hops" "$i" "node-${node_letter} hops >= ${i}"
  else
    fail_test "Announce not received on node-${node_letter}"
  fi
done

suite_result "03_announce_multihop"
