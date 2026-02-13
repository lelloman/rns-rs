#!/usr/bin/env bash
# Suite 15: Resource Transfer — resource transfer over links
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="15_resource_transfer"
echo "Suite 15: Resource transfer"

if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  skip_suite "Resource transfer test requires chain or mesh topology"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"

# Establish link: Node-B (initiator) → Node-A (listener)
echo "  Establishing link B → A..."
LINK_RESULT=$(establish_link "$PORT_B" "$PORT_A" "testresource" "xfer") || true
LINK_ID=$(echo "$LINK_RESULT" | awk '{print $1}')
DEST_A=$(echo "$LINK_RESULT" | awk '{print $2}')
echo "  Link: ${LINK_ID}, Dest: ${DEST_A}"

if [[ -z "$LINK_ID" || "$LINK_ID" == "null" ]]; then
  fail_test "Failed to establish link"
  suite_result "15_resource_transfer"
  exit 0
fi

# Generate 1KB of test data
DATA_B64=$(dd if=/dev/urandom bs=1024 count=1 2>/dev/null | base64 -w0)
META_B64=$(echo -n '{"filename":"test.bin","size":1024}' | base64)

echo "  Node-B sending resource (1KB + metadata)..."
send_resource "$PORT_B" "$LINK_ID" "$DATA_B64" "$META_B64"

# Poll Node-A's resource_events for a "received" event
echo "  Waiting for resource received event on Node-A..."
if poll_until "$PORT_A" "/api/resource_events" \
  "[.resource_events[] | select(.event_type == \"received\")] | length | . > 0" \
  "true" 60; then

  # Verify received data matches
  recv_data=$(get_resource_events "$PORT_A" | jq -r \
    "[.resource_events[] | select(.event_type == \"received\")] | last | .data_base64")
  assert_eq "$recv_data" "$DATA_B64" "Resource data matches"

  # Verify metadata preserved
  recv_meta=$(get_resource_events "$PORT_A" | jq -r \
    "[.resource_events[] | select(.event_type == \"received\")] | last | .metadata_base64")
  assert_eq "$recv_meta" "$META_B64" "Resource metadata matches"
else
  fail_test "Resource not received on Node-A"
fi

# Check for "completed" event on sender side
echo "  Checking resource completed event on Node-B..."
has_completed=$(get_resource_events "$PORT_B" | jq -r \
  "[.resource_events[] | select(.event_type == \"completed\")] | length")
assert_ge "$has_completed" "1" "Resource completed event on Node-B"

suite_result "15_resource_transfer"
