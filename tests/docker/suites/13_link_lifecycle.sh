#!/usr/bin/env bash
# Suite 13: Link Lifecycle — create, verify, close
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="13_link_lifecycle"
echo "Suite 13: Link lifecycle"

if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  skip_suite "Link lifecycle test requires chain or mesh topology"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"

# Node-A creates inbound single destination and announces
DEST_A=$(create_destination "$PORT_A" "single" "testlink" "lifecycle")
echo "  Node-A destination: ${DEST_A}"
announce "$PORT_A" "$DEST_A"
echo "  Node-A announced"

# Wait for Node-B to recall Node-A's identity
echo "  Waiting for identity recall on Node-B..."
if ! poll_until "$PORT_B" "/api/identity/${DEST_A}" ".dest_hash" "$DEST_A" 30; then
  fail_test "Identity not recalled on Node-B"
  suite_result "13_link_lifecycle"
  exit 0
fi
echo "  Identity recalled"

# Node-B creates link to Node-A
LINK_ID=$(create_link "$PORT_B" "$DEST_A")
echo "  Link created: ${LINK_ID}"

if [[ -z "$LINK_ID" || "$LINK_ID" == "null" ]]; then
  fail_test "create_link returned empty or null"
  suite_result "13_link_lifecycle"
  exit 0
fi

# Poll both nodes until link is active
echo "  Waiting for link active on Node-B (initiator)..."
if poll_until "$PORT_B" "/api/links" \
  ".links[] | select(.link_id == \"${LINK_ID}\") | .state" \
  "active" 30; then
  pass_test "Link active on Node-B"
else
  fail_test "Link not active on Node-B"
  suite_result "13_link_lifecycle"
  exit 0
fi

echo "  Waiting for link active on Node-A (listener)..."
if poll_until "$PORT_A" "/api/links" \
  ".links[] | select(.link_id == \"${LINK_ID}\") | .state" \
  "active" 30; then
  pass_test "Link active on Node-A"
else
  fail_test "Link not active on Node-A"
fi

# Assert Node-B is initiator
is_init=$(get_links "$PORT_B" | jq -r ".links[] | select(.link_id == \"${LINK_ID}\") | .is_initiator")
assert_eq "$is_init" "true" "Node-B is initiator"

# Assert RTT > 0 on the link
rtt=$(get_links "$PORT_B" | jq -r ".links[] | select(.link_id == \"${LINK_ID}\") | .rtt")
if [[ -n "$rtt" && "$rtt" != "null" ]]; then
  # rtt is a float; check it's > 0 via awk
  rtt_positive=$(echo "$rtt" | awk '{print ($1 > 0) ? "yes" : "no"}')
  assert_eq "$rtt_positive" "yes" "Link RTT > 0"
else
  fail_test "Link RTT is null or empty"
fi

# Close link from Node-B
echo "  Closing link from Node-B..."
close_link "$PORT_B" "$LINK_ID"

# Poll until link disappears from Node-B
echo "  Waiting for link to disappear from Node-B..."
if poll_until "$PORT_B" "/api/links" \
  "[.links[] | select(.link_id == \"${LINK_ID}\")] | length" \
  "0" 30; then
  pass_test "Link removed from Node-B"
else
  fail_test "Link still present on Node-B after close"
fi

# Poll until link disappears from Node-A
echo "  Waiting for link to disappear from Node-A..."
if poll_until "$PORT_A" "/api/links" \
  "[.links[] | select(.link_id == \"${LINK_ID}\")] | length" \
  "0" 30; then
  pass_test "Link removed from Node-A"
else
  fail_test "Link still present on Node-A after close"
fi

# Check link_events for established and closed events
echo "  Checking link events on Node-B..."
has_established=$(get_link_events "$PORT_B" | jq -r \
  "[.link_events[] | select(.link_id == \"${LINK_ID}\" and .event_type == \"established\")] | length")
assert_ge "$has_established" "1" "Link established event on Node-B"

has_closed=$(get_link_events "$PORT_B" | jq -r \
  "[.link_events[] | select(.link_id == \"${LINK_ID}\" and .event_type == \"closed\")] | length")
assert_ge "$has_closed" "1" "Link closed event on Node-B"

suite_result "13_link_lifecycle"
