#!/usr/bin/env bash
# Suite 11: Star Announce — announce fan-out through hub
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="11_star_announce"
echo "Suite 11: Star announce fan-out"

if [[ "${TOPO_TYPE:-chain}" != "star" ]]; then
  skip_suite "Star announce test requires star topology"
fi

N="${TOPO_N:-5}"
if (( N < 4 )); then
  skip_suite "Need star-4 or larger"
fi

HUB="${HUB_PORT:?Need HUB_PORT}"

# Spoke-01 creates destination and announces
SPOKE_01="${SPOKE_01_PORT:?Need SPOKE_01_PORT}"
DEST=$(create_destination "$SPOKE_01" "single" "teststarann" "fanout")
echo "  Spoke-01 dest: ${DEST}"
announce "$SPOKE_01" "$DEST"
echo "  Spoke-01 announced"

# Hub should receive with hops=1
echo "  Checking hub..."
if poll_until "$HUB" "/api/announces" \
  ".announces[] | select(.dest_hash == \"${DEST}\") | .dest_hash" \
  "$DEST" 30; then

  hops=$(get_announces "$HUB" | jq -r ".announces[] | select(.dest_hash == \"${DEST}\") | .hops")
  assert_eq "$hops" "1" "Hub received announce with hops=1"
else
  fail_test "Hub did not receive announce"
fi

# Other spokes should receive with hops=2 (spoke-01 -> hub -> spoke-N)
for (( i=2; i<N; i++ )); do
  varname="SPOKE_$(printf '%02d' "$i")_PORT"
  port="${!varname}"

  echo "  Checking spoke-$(printf '%02d' "$i")..."
  if poll_until "$port" "/api/announces" \
    ".announces[] | select(.dest_hash == \"${DEST}\") | .dest_hash" \
    "$DEST" 30; then

    hops=$(get_announces "$port" | jq -r ".announces[] | select(.dest_hash == \"${DEST}\") | .hops")
    assert_eq "$hops" "2" "Spoke-$(printf '%02d' "$i") received announce with hops=2"
  else
    fail_test "Spoke-$(printf '%02d' "$i") did not receive announce"
  fi
done

suite_result "11_star_announce"
