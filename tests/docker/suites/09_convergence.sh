#!/usr/bin/env bash
# Suite 09: Convergence — all-to-all announce convergence timing on star
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="09_convergence"
echo "Suite 09: Convergence timing"

# Collect all ports into an array
declare -a PORTS=()
declare -a NAMES=()
declare -a DEST_HASHES=()

if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  PORTS+=("${HUB_PORT:?Need HUB_PORT}")
  NAMES+=("hub")

  for (( i=1; i<TOPO_N; i++ )); do
    varname="SPOKE_$(printf '%02d' "$i")_PORT"
    PORTS+=("${!varname}")
    NAMES+=("spoke-$(printf '%02d' "$i")")
  done
else
  # Chain topology
  for (( i=0; i<TOPO_N; i++ )); do
    node_letter=$(printf "\\$(printf '%03o' "$(( i + 97 ))")")
    varname="NODE_$(echo "$node_letter" | tr '[:lower:]' '[:upper:]')_PORT"
    PORTS+=("${!varname}")
    NAMES+=("node-${node_letter}")
  done
fi

TOTAL=${#PORTS[@]}
EXPECTED_ANNOUNCES=$(( TOTAL - 1 ))

echo "  Total nodes: ${TOTAL}"
echo "  Expected announces per node: ${EXPECTED_ANNOUNCES}"

# All nodes create destinations and announce simultaneously
for (( i=0; i<TOTAL; i++ )); do
  dh=$(create_destination "${PORTS[$i]}" "single" "testconverge" "node${i}")
  announce "${PORTS[$i]}" "$dh"
  DEST_HASHES+=("$dh")
  echo "  ${NAMES[$i]} announced: ${dh}"
done

# Measure convergence: poll until every node has all other announces
START_TIME=$SECONDS
TIMEOUT=60

converged=true
for (( i=0; i<TOTAL; i++ )); do
  echo "  Waiting for ${NAMES[$i]} to receive ${EXPECTED_ANNOUNCES} announces..."
  if poll_count "${PORTS[$i]}" "/api/announces" ".announces" "$EXPECTED_ANNOUNCES" "$TIMEOUT"; then
    echo "  ${NAMES[$i]} converged"
  else
    fail_test "${NAMES[$i]} did not converge"
    converged=false
  fi
done

ELAPSED=$(( SECONDS - START_TIME ))
echo "  Convergence time: ${ELAPSED}s"

if $converged; then
  assert_le "$ELAPSED" "60" "Convergence within 60s"
fi

suite_result "09_convergence"
