#!/usr/bin/env bash
# Suite 17: Concurrent Links — multiple simultaneous links to hub
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="17_concurrent_links"
echo "Suite 17: Concurrent links"

if [[ "${TOPO_TYPE:-chain}" != "star" ]]; then
  skip_suite "Concurrent links test requires star topology"
fi

N="${TOPO_N:-5}"
if (( N < 4 )); then
  skip_suite "Need star-4 or larger for concurrent links test"
fi

HUB="${HUB_PORT:?Need HUB_PORT}"
SPOKE_COUNT=$(( N - 1 ))
echo "  Star topology: 1 hub + ${SPOKE_COUNT} spokes"

# Hub creates inbound destination and announces
DEST_HUB=$(create_destination "$HUB" "single" "testconclink" "hub")
echo "  Hub destination: ${DEST_HUB}"
announce "$HUB" "$DEST_HUB"
echo "  Hub announced"

# Wait for all spokes to recall hub's identity
echo "  Waiting for all spokes to recall hub identity..."
declare -a SPOKE_PORTS=()
for (( i=1; i<N; i++ )); do
  varname="SPOKE_$(printf '%02d' "$i")_PORT"
  port="${!varname}"
  SPOKE_PORTS+=("$port")

  if ! poll_until "$port" "/api/identity/${DEST_HUB}" ".dest_hash" "$DEST_HUB" 30; then
    fail_test "Spoke-$(printf '%02d' "$i") cannot recall hub identity"
    suite_result "17_concurrent_links"
    exit 0
  fi
done
echo "  All spokes recalled hub identity"

# All spokes create links to hub simultaneously (fire-and-forget)
echo "  All spokes creating links..."
declare -a LINK_IDS=()
for (( i=0; i<SPOKE_COUNT; i++ )); do
  lid=$(create_link "${SPOKE_PORTS[$i]}" "$DEST_HUB")
  LINK_IDS+=("$lid")
  echo "  Spoke-$(printf '%02d' $((i+1))) link: ${lid}"
done

# Poll hub until all links are active
echo "  Waiting for hub to have ${SPOKE_COUNT} active links..."
if poll_until "$HUB" "/api/links" \
  "[.links[] | select(.state == \"active\")] | length | . >= ${SPOKE_COUNT}" \
  "true" 60; then
  hub_link_count=$(get_links "$HUB" | jq "[.links[] | select(.state == \"active\")] | length")
  assert_ge "$hub_link_count" "$SPOKE_COUNT" "Hub has >= ${SPOKE_COUNT} active links"
else
  hub_link_count=$(get_links "$HUB" | jq "[.links[] | select(.state == \"active\")] | length")
  fail_test "Hub active links (${hub_link_count}) < ${SPOKE_COUNT}"
fi

# Each spoke sends a channel message with unique ID
echo "  Each spoke sending channel message..."
for (( i=0; i<SPOKE_COUNT; i++ )); do
  unique_payload=$(echo -n "spoke-${i}-msg" | base64)
  send_channel "${SPOKE_PORTS[$i]}" "${LINK_IDS[$i]}" 50 "$unique_payload" || true
done

# Poll hub until all channel messages received
echo "  Waiting for hub to receive ${SPOKE_COUNT} channel messages..."
if poll_count "$HUB" "/api/packets" \
  "[.packets[] | select(.dest_hash | startswith(\"channel:\"))]" \
  "$SPOKE_COUNT" 60; then
  pass_test "Hub received all ${SPOKE_COUNT} channel messages"
else
  chan_count=$(get_packets "$HUB" | jq "[.packets[] | select(.dest_hash | startswith(\"channel:\"))] | length")
  fail_test "Hub channel messages (${chan_count}) < ${SPOKE_COUNT}"
fi

# Verify each unique payload is present
echo "  Verifying unique payloads..."
all_present=true
for (( i=0; i<SPOKE_COUNT; i++ )); do
  expected_payload=$(echo -n "spoke-${i}-msg" | base64)
  found=$(get_packets "$HUB" | jq -r \
    "[.packets[] | select(.data_base64 == \"${expected_payload}\")] | length")
  if (( found < 1 )); then
    fail_test "Spoke-${i} payload not found on hub"
    all_present=false
  fi
done
if $all_present; then
  pass_test "All unique spoke payloads present on hub"
fi

suite_result "17_concurrent_links"
