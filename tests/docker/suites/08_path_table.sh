#!/usr/bin/env bash
# Suite 08: Path Table — verify hop counts in path table across chain
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="08_path_table"
echo "Suite 08: Path table hop counts"

if [[ "${TOPO_TYPE:-chain}" != "chain" ]]; then
  skip_suite "Path table test requires chain topology"
fi

N="${TOPO_N:-5}"
if (( N < 3 )); then
  skip_suite "Need chain-3 or longer"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"

# Node-a announces
DEST_A=$(create_destination "$PORT_A" "single" "testpath" "table")
announce "$PORT_A" "$DEST_A"
echo "  Node-a announced: ${DEST_A}"

# Wait for announce to propagate to the last node
last_idx=$(( N - 1 ))
last_letter=$(printf "\\$(printf '%03o' "$(( last_idx + 97 ))")")
last_varname="NODE_$(echo "$last_letter" | tr '[:lower:]' '[:upper:]')_PORT"
last_port="${!last_varname}"

echo "  Waiting for announce to reach node-${last_letter}..."
poll_until "$last_port" "/api/announces" \
  ".announces[] | select(.dest_hash == \"${DEST_A}\") | .dest_hash" \
  "$DEST_A" 60 || true

# Give a moment for path tables to settle
sleep 2

# Check path table on each node
for (( i=1; i<N; i++ )); do
  node_letter=$(printf "\\$(printf '%03o' "$(( i + 97 ))")")
  varname="NODE_$(echo "$node_letter" | tr '[:lower:]' '[:upper:]')_PORT"
  port="${!varname}"

  hops=$(get_paths "$port" "$DEST_A" | jq -r ".paths[] | select(.hash == \"${DEST_A}\") | .hops" 2>/dev/null) || hops=""

  if [[ -n "$hops" && "$hops" != "null" ]]; then
    assert_eq "$hops" "$i" "node-${node_letter} path hops == ${i}"
  else
    fail_test "node-${node_letter} has no path entry for ${DEST_A}"
  fi
done

suite_result "08_path_table"
