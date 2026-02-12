#!/usr/bin/env bash
# Suite 10: Scale — star-30 scale test with announce convergence + packet delivery
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="10_scale"
echo "Suite 10: Scale test"

if [[ "${TOPO_TYPE:-chain}" != "star" ]]; then
  skip_suite "Scale test requires star topology"
fi

N="${TOPO_N:-30}"
if (( N < 10 )); then
  skip_suite "Need star-10 or larger for scale test"
fi
HUB="${HUB_PORT:?Need HUB_PORT}"
SPOKE_COUNT=$(( N - 1 ))

echo "  Star topology: 1 hub + ${SPOKE_COUNT} spokes"

# Each spoke announces
declare -a DEST_HASHES=()
declare -a SPOKE_PORTS=()

for (( i=1; i<N; i++ )); do
  varname="SPOKE_$(printf '%02d' "$i")_PORT"
  port="${!varname}"
  SPOKE_PORTS+=("$port")

  dh=$(create_destination "$port" "single" "testscale" "spoke${i}" "all")
  announce "$port" "$dh"
  DEST_HASHES+=("$dh")
done
echo "  All ${SPOKE_COUNT} spokes announced"

# Poll hub until all announces received
echo "  Waiting for hub to receive ${SPOKE_COUNT} announces..."
if poll_count "$HUB" "/api/announces" ".announces" "$SPOKE_COUNT" 120; then
  pass_test "Hub received all ${SPOKE_COUNT} announces"
else
  fail_test "Hub did not receive all announces"
  suite_result "10_scale"
  exit 0
fi

# Pick 5 random spoke pairs and test packet delivery
echo "  Testing packet delivery between spoke pairs..."
for trial in $(seq 1 5); do
  # Pick two different random spokes
  src_idx=$(( RANDOM % SPOKE_COUNT ))
  dst_idx=$(( (src_idx + trial) % SPOKE_COUNT ))

  src_port="${SPOKE_PORTS[$src_idx]}"
  dst_port="${SPOKE_PORTS[$dst_idx]}"
  dst_hash="${DEST_HASHES[$dst_idx]}"

  echo "  Trial ${trial}: spoke-$(printf '%02d' $((src_idx+1))) -> spoke-$(printf '%02d' $((dst_idx+1)))"

  # Wait for identity recall on source spoke
  if ! poll_until "$src_port" "/api/identity/${dst_hash}" ".dest_hash" "$dst_hash" 30; then
    fail_test "Trial ${trial}: source cannot recall destination identity"
    continue
  fi

  # Send packet
  out_dest=$(create_outbound_dest "$src_port" "testscale" "spoke$((dst_idx+1))" "$dst_hash")
  data_b64=$(echo -n "scale-test-${trial}" | base64)
  send_result=$(send_packet "$src_port" "$out_dest" "$data_b64")
  pkt_hash=$(echo "$send_result" | jq -r '.packet_hash')

  # Verify delivery
  if poll_until "$dst_port" "/api/packets" \
    ".packets[] | select(.packet_hash == \"${pkt_hash}\") | .packet_hash" \
    "$pkt_hash" 30; then
    pass_test "Trial ${trial} delivered"
  else
    fail_test "Trial ${trial} not delivered"
  fi
done

suite_result "10_scale"
