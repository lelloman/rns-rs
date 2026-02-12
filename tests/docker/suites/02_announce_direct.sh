#!/usr/bin/env bash
# Suite 02: Direct Announce — 1-hop announce propagation on chain
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="02_announce_direct"
echo "Suite 02: Direct announce (1-hop)"

if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  skip_suite "Direct announce test requires chain or mesh topology"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"

# Node-a creates and announces a single destination
DEST_HASH=$(create_destination "$PORT_A" "single" "testannounce" "direct")
echo "  Created destination on node-a: ${DEST_HASH}"

announce "$PORT_A" "$DEST_HASH"
echo "  Announced from node-a"

# Poll node-b for the announce
if poll_until "$PORT_B" "/api/announces" \
  ".announces[] | select(.dest_hash == \"${DEST_HASH}\") | .dest_hash" \
  "$DEST_HASH" 30; then
  echo "  Announce received on node-b"
else
  fail_test "Announce not received on node-b within timeout"
fi

# Check hop count on node-b (should be 1)
hops=$(get_announces "$PORT_B" | jq -r ".announces[] | select(.dest_hash == \"${DEST_HASH}\") | .hops")
assert_eq "$hops" "1" "Announce hops on node-b should be 1"

suite_result "02_announce_direct"
