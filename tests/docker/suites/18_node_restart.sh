#!/usr/bin/env bash
# Suite 18: Node Restart — container restart recovery
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="18_node_restart"
echo "Suite 18: Node restart recovery"

if [[ "${TOPO_TYPE:-chain}" != "chain" ]]; then
  skip_suite "Node restart test requires chain topology"
fi

N="${TOPO_N:-3}"
if (( N < 3 )); then
  skip_suite "Need chain-3 or longer for node restart test"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"

# Determine last node port
last_idx=$(( N - 1 ))
last_letter=$(printf "\\$(printf '%03o' "$(( last_idx + 97 ))")")
last_varname="NODE_$(echo "$last_letter" | tr '[:lower:]' '[:upper:]')_PORT"
PORT_LAST="${!last_varname}"
echo "  Node-A: port ${PORT_A}, Node-B (middle): port ${PORT_B}, Last (node-${last_letter}): port ${PORT_LAST}"

COMPOSE_FILE="${SCRIPT_DIR}/configs/${TOPOLOGY}/docker-compose.yml"

# Step 1: Establish baseline — Node-A announces, last node receives
DEST_A=$(create_destination "$PORT_A" "single" "testrestart" "baseline")
echo "  Node-A destination: ${DEST_A}"
announce "$PORT_A" "$DEST_A"
echo "  Node-A announced"

echo "  Waiting for announce on last node..."
if ! poll_until "$PORT_LAST" "/api/announces" \
  ".announces[] | select(.dest_hash == \"${DEST_A}\") | .dest_hash" \
  "$DEST_A" 60; then
  fail_test "Baseline announce not received on last node"
  suite_result "18_node_restart"
  exit 0
fi
pass_test "Baseline announce received on last node"

# Step 2: Restart Node-B (middle node)
echo "  Restarting node-b..."
docker compose -f "$COMPOSE_FILE" restart node-b

# Step 3: Wait for Node-B health check to pass
echo "  Waiting for node-b health..."
if poll_until "$PORT_B" "/health" ".status" "healthy" 60; then
  pass_test "Node-B healthy after restart"
else
  fail_test "Node-B not healthy after restart"
  suite_result "18_node_restart"
  exit 0
fi

# Step 4: Clear last node's announces so we can detect new ones
ctl_get "$PORT_LAST" "/api/announces?clear=true" > /dev/null 2>&1 || true

# Step 5: Node-A re-announces
DEST_A2=$(create_destination "$PORT_A" "single" "testrestart" "recovery")
echo "  Node-A new destination: ${DEST_A2}"
announce "$PORT_A" "$DEST_A2"
echo "  Node-A re-announced"

# Step 6: Poll last node for announce re-propagation through restarted Node-B
echo "  Waiting for re-announce on last node (through restarted node-b)..."
if poll_until "$PORT_LAST" "/api/announces" \
  ".announces[] | select(.dest_hash == \"${DEST_A2}\") | .dest_hash" \
  "$DEST_A2" 60; then
  pass_test "Announce propagated through restarted Node-B"
else
  fail_test "Announce not propagated through restarted Node-B"
fi

suite_result "18_node_restart"
