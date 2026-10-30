#!/usr/bin/env bash
# Suite 21: Stamped emission — the asynchronous stamper queue end to end.
#
# Reticulum 1.6.0 can stamp the announces and path requests a node emits
# (Transport.STAMP_DESTINATIONS / STAMP_PRS, both off by default on both
# sides). The stamps are ground on a background stamper worker so the API
# returns at once. This suite switches both flags on for node-a through the
# `global.stamp_*` runtime config keys and checks, with real binaries over
# TCP, that:
#   - node-b validates and counts a stamped path request from node-a,
#   - node-a's stamped announce is validated by node-b and node-c, which
#     record the stamp value and the announced link request cost,
#   - the destination stamp is persisted on node-a for reuse,
#   - the flags read back as false again once reset.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="21_stamped_emission"
echo "Suite 21: Stamped announces and path requests"

if [[ "${TOPO_TYPE:-chain}" != "chain" ]]; then
  skip_suite "Stamped emission test requires chain topology"
fi

N="${TOPO_N:-3}"
if (( N < 3 )); then
  skip_suite "Need chain-3 or longer for stamped emission test"
fi

if ! command -v docker &>/dev/null; then
  skip_suite "docker CLI is required to toggle runtime config inside node-a"
fi

PORT_A="${NODE_A_PORT:?Need NODE_A_PORT}"
PORT_B="${NODE_B_PORT:?Need NODE_B_PORT}"
PORT_C="${NODE_C_PORT:?Need NODE_C_PORT}"

# Protocol constants (docs/configuration.md, Stamps).
DESTINATION_STAMP_COST=23.5
# LR_COST is 12.5 (f57fa265), announced with its fraction (796ef2d4).
LINK_REQUEST_STAMP_COST=12.5

# ── Runtime config through the daemon's RPC port inside node-a ──────────────

runtime_get() {
  docker exec node-a rns-ctl config get "$1" --config /data --value-only 2>/dev/null
}

runtime_set() {
  docker exec node-a rns-ctl config set "$1" "$2" --config /data >/dev/null
}

runtime_reset() {
  docker exec node-a rns-ctl config reset "$1" --config /data >/dev/null 2>&1 || true
}

# Never leave stamping switched on for later suites.
trap 'runtime_reset global.stamp_destinations; runtime_reset global.stamp_path_requests' EXIT

# Stamped path requests accepted on any interface of the node at PORT.
stamped_path_requests() {
  local port="$1"
  ctl_get "$port" "/api/interfaces" | jq '[.interfaces[].stamped_path_requests] | add // 0'
}

# poll_stamped_path_requests PORT MIN TIMEOUT
poll_stamped_path_requests() {
  local port="$1" min="$2" timeout="${3:-60}"
  local deadline=$((SECONDS + timeout))
  local count=0
  while (( SECONDS < deadline )); do
    count=$(stamped_path_requests "$port")
    if (( count >= min )); then
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT: stamped path requests on port ${port}: expected >= ${min}, got ${count}" >&2
  return 1
}

# poll_stamp_value PORT DEST_HASH MIN TIMEOUT — wait until the node recorded a
# stamp of at least MIN for DEST_HASH. Values and costs are fractional, so jq
# compares them.
poll_stamp_value() {
  local port="$1" dest_hash="$2" min="$3" timeout="${4:-90}"
  local deadline=$((SECONDS + timeout))
  local value=0
  while (( SECONDS < deadline )); do
    value=$(get_identity "$port" "$dest_hash" 2>/dev/null | jq -r '.stamp_value // 0')
    if jq -en --argjson value "$value" --argjson min "$min" '$value >= $min' >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT: stamp value for ${dest_hash} on port ${port}: expected >= ${min}, got ${value}" >&2
  return 1
}

# ── Defaults ─────────────────────────────────────────────────────────────────

assert_eq "$(runtime_get global.stamp_path_requests)" "false" "stamp_path_requests defaults to false"
assert_eq "$(runtime_get global.stamp_destinations)" "false" "stamp_destinations defaults to false"

# ── Stamped path request ─────────────────────────────────────────────────────
# node-c announces a destination; node-a, with STAMP_PRS on, asks node-b for
# the path. The request waits for the stamper worker, then node-b validates
# the stamp (cost 19 over destination hash and tag) and counts it.

DEST_C=$(create_destination "$PORT_C" "single" "teststamp" "pr")
echo "  Created destination on node-c: ${DEST_C}"
announce "$PORT_C" "$DEST_C"
if ! poll_until "$PORT_A" "/api/paths" \
  ".paths[] | select(.hash == \"${DEST_C}\") | .hash" "$DEST_C" 60; then
  fail_test "node-a never learned the path to node-c's destination"
fi

STAMPED_BEFORE=$(stamped_path_requests "$PORT_B")
runtime_set global.stamp_path_requests true
assert_eq "$(runtime_get global.stamp_path_requests)" "true" "stamp_path_requests switched on at runtime"

request_path "$PORT_A" "$DEST_C" >/dev/null
if poll_stamped_path_requests "$PORT_B" "$(( STAMPED_BEFORE + 1 ))" 60; then
  pass_test "node-b validated a stamped path request from node-a"
else
  fail_test "node-b never counted a stamped path request from node-a"
fi

# ── Stamped announce ─────────────────────────────────────────────────────────
# node-a's first announce of a new destination has no persisted stamp: the
# API returns at once and the worker grinds a 23-bit stamp, persists it and
# emits the announce with the stamp and link request cost appended.

DEST_A=$(create_destination "$PORT_A" "single" "teststamp" "announce")
echo "  Created destination on node-a: ${DEST_A}"
runtime_set global.stamp_destinations true
assert_eq "$(runtime_get global.stamp_destinations)" "true" "stamp_destinations switched on at runtime"

ANNOUNCE_START=$SECONDS
announce "$PORT_A" "$DEST_A"
assert_le "$(( SECONDS - ANNOUNCE_START ))" 2 "announce API returned without grinding the stamp"

for node in b c; do
  varname="NODE_$(echo "$node" | tr '[:lower:]' '[:upper:]')_PORT"
  port="${!varname}"
  if poll_stamp_value "$port" "$DEST_A" "$DESTINATION_STAMP_COST" 90; then
    pass_test "node-${node} recorded a destination stamp of at least ${DESTINATION_STAMP_COST} for node-a"
    lr_cost=$(get_identity "$port" "$DEST_A" | jq -r '.lr_cost')
    assert_eq "$lr_cost" "$LINK_REQUEST_STAMP_COST" "node-${node} recorded node-a's announced link request cost"
  else
    fail_test "node-${node} never recorded a valid destination stamp for node-a"
  fi
done

if docker exec node-a ls /data/storage/stamps 2>/dev/null | grep -qx "${DEST_A}.dstamp"; then
  pass_test "node-a persisted the destination stamp for reuse"
else
  fail_test "node-a did not persist the destination stamp" \
    "$(docker exec node-a ls /data/storage/stamps 2>&1 || true)"
fi

# ── Reset ────────────────────────────────────────────────────────────────────

runtime_reset global.stamp_destinations
runtime_reset global.stamp_path_requests
assert_eq "$(runtime_get global.stamp_destinations)" "false" "stamp_destinations reset to default"
assert_eq "$(runtime_get global.stamp_path_requests)" "false" "stamp_path_requests reset to default"

suite_result "21_stamped_emission"
