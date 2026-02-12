#!/usr/bin/env bash
# Suite 07: Identity Recall — verify identity recall after announce on star
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="07_identity_recall"
echo "Suite 07: Identity recall"

# This test works best on star topology but adapts to chain
if [[ "${TOPO_TYPE:-chain}" == "star" ]]; then
  HUB_PORT="${HUB_PORT:?Need HUB_PORT}"
  N="${TOPO_N:-5}"

  dest_hashes=()

  # Each spoke creates a unique destination and announces
  for (( i=1; i<N; i++ )); do
    varname="SPOKE_$(printf '%02d' "$i")_PORT"
    port="${!varname}"
    dh=$(create_destination "$port" "single" "testrecall" "spoke${i}")
    announce "$port" "$dh"
    dest_hashes+=("$dh")
    echo "  Spoke-$(printf '%02d' "$i") announced: ${dh}"
  done

  # Poll hub for all identity recalls
  for (( i=0; i<${#dest_hashes[@]}; i++ )); do
    dh="${dest_hashes[$i]}"
    spoke_num=$(( i + 1 ))
    echo "  Checking hub recall for spoke-$(printf '%02d' "$spoke_num")..."
    if poll_until "$HUB_PORT" "/api/identity/${dh}" ".dest_hash" "$dh" 30; then
      pass_test "Hub recalled spoke-$(printf '%02d' "$spoke_num")"
    else
      fail_test "Hub did not recall spoke-$(printf '%02d' "$spoke_num")"
    fi
  done

else
  # Chain fallback: a announces, others recall
  PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
  DEST_A=$(create_destination "$PORT_A" "single" "testrecall" "chain")
  announce "$PORT_A" "$DEST_A"
  echo "  Node-a announced: ${DEST_A}"

  PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"
  if poll_until "$PORT_B" "/api/identity/${DEST_A}" ".dest_hash" "$DEST_A" 30; then
    pass_test "Node-b recalled identity"
  else
    fail_test "Node-b did not recall identity"
  fi
fi

suite_result "07_identity_recall"
