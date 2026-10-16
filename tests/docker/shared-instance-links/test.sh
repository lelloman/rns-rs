#!/usr/bin/env bash
# test.sh — Shared instance sibling and adjacent-peer links E2E test
#
# Covers the fix for GitHub issue #183: a shared instance daemon
# (share_instance=Yes, enable_transport=False) dropped HEADER_1 packets
# (no transport header) addressed to destinations behind its local
# clients. That broke:
#   (a) sibling clients on the same daemon linking to each other, and
#   (b) nodes directly adjacent to the daemon (1 hop) linking to clients
#       behind it, since Python sends HEADER_1 for 1-hop destinations.
#
# Architecture (see docker-compose.yml):
#   sil-daemon      — rns-ctl daemon (shared instance) + rns-rs shared
#                     clients A (8091) and B (8092)
#   sil-py-sibling  — Python RNS shared client of the same daemon (8093)
#   sil-py-external — Python RNS node with a TCP link to the daemon (8094)
#
# The test:
#   1. All four nodes are up and attached
#   2. rns-rs sibling link B -> A: channel message, resource, close
#   3. Python sibling -> rns-rs A link, packet with proof, resource
#   4. rns-rs A -> Python sibling link, packet
#   5. Python external -> rns-rs A link (HEADER_1 from adjacent peer)
#   6. rns-rs A -> Python external link
#   7. Python external -> Python sibling link through the rns-rs daemon
#   8. Single DATA packet with proof between rns-rs siblings B -> A
#
# run.sh runs this once per daemon enable_transport mode (exported as
# DAEMON_ENABLE_TRANSPORT). With transport disabled, the rns-rs shared
# instance does not yet rebroadcast its local clients' announces to other
# interfaces, nor answer path requests for them, as Python does
# (Transport.py, "transport_enabled() or is_from_local_client"), so
# py-external cannot discover a path to destinations behind the daemon.
# Steps 5 and 7 are therefore skipped in that mode and covered by the
# transport-enabled pass, where py-external still sees them at 1 hop and
# sends HEADER_1 packets.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/helpers.sh"

TRANSPORT="${DAEMON_ENABLE_TRANSPORT:-False}"
_CURRENT_SUITE="shared-instance-links-transport-${TRANSPORT,,}"

PORT_A=8091
PORT_B=8092
PORT_PY_SIB=8093
PORT_PY_EXT=8094
APP="e2esil"

echo "=== Shared Instance Links E2E Test (issue #183, enable_transport=${TRANSPORT}) ==="

# ── Helpers ─────────────────────────────────────────────────────────────────

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

# external_discovery_supported — see the header: false on a daemon without
# transport, where py-external cannot learn paths to the daemon's clients.
external_discovery_supported() { [[ "${TRANSPORT,,}" == "true" ]]; }

skip_step() {
  echo "  SKIP: $1"
  record_result "SKIP" "$1"
}

# py_post PORT PATH BODY — like ctl_post, but prints the error JSON on 500.
py_post() {
  local port="$1" path="$2" body="${3:-"{}"}"
  curl -s -X POST -H "Content-Type: application/json" \
    -d "$body" "http://localhost:${port}${path}"
}

# py_link PORT DEST_HASH ASPECT — POST /link on a Python node, echoes JSON.
py_link() {
  local port="$1" dest="$2" aspect="$3"
  py_post "$port" "/link" "$(jq -n --arg dh "$dest" --arg a "$aspect" \
    '{dest_hash: $dh, aspects: [$a], timeout: 30}')"
}

# py_send PORT LINK_ID DATA_B64 — packet on a Python link, echoes JSON.
py_send() {
  local port="$1" link_id="$2" data="$3"
  py_post "$port" "/link/send" "$(jq -n --arg l "$link_id" --arg d "$data" \
    '{link_id: $l, data: $d, timeout: 15}')"
}

# py_resource PORT LINK_ID DATA_B64 — resource on a Python link, echoes JSON.
py_resource() {
  local port="$1" link_id="$2" data="$3"
  py_post "$port" "/link/resource" "$(jq -n --arg l "$link_id" --arg d "$data" \
    '{link_id: $l, data: $d, timeout: 30}')"
}

# check_rns_link_active PORT LINK_ID MSG
check_rns_link_active() {
  local port="$1" link_id="$2" msg="$3"
  if poll_until "$port" "/api/links" \
    ".links[] | select(.link_id == \"${link_id}\") | .state" "active" 30; then
    pass_test "$msg"
  else
    fail_test "$msg"
  fi
}

# check_rns_resource PORT LINK_ID DATA_B64 MSG — resource received on rns-ctl.
check_rns_resource() {
  local port="$1" link_id="$2" data="$3" msg="$4"
  if poll_until "$port" "/api/resource_events" \
    "[.resource_events[] | select(.link_id == \"${link_id}\" and .event_type == \"received\" and .data_base64 == \"${data}\")] | length > 0" \
    "true" 30; then
    pass_test "$msg"
  else
    fail_test "$msg"
  fi
}

# check_py_event PORT TYPE LINK_ID DATA_B64|"" MSG — event recorded on Python.
check_py_event() {
  local port="$1" type="$2" link_id="$3" data="$4" msg="$5"
  local filter=".type == \"${type}\" and .link_id == \"${link_id}\""
  if [[ -n "$data" ]]; then
    filter="${filter} and .data == \"${data}\""
  fi
  if poll_until "$port" "/events" "[.events[] | select(${filter})] | length > 0" \
    "true" 30; then
    pass_test "$msg"
  else
    fail_test "$msg"
  fi
}

# py_to_rns PY_PORT PY_NAME ASPECT — Python node links to a fresh destination
# on rns-rs client A, sends a proved packet and a resource over the link.
py_to_rns() {
  local py_port="$1" name="$2" aspect="$3"
  echo ""
  echo "--- ${name} -> rns-rs client A ---"

  local dest
  dest=$(create_destination "$PORT_A" "single" "$APP" "$aspect" || true)
  if [[ -z "$dest" || "$dest" == "null" ]]; then
    fail_test "${name}->A: create destination on A"
    return
  fi
  announce "$PORT_A" "$dest" || true
  echo "  A destination: ${dest}"

  if poll_until "$py_port" "/identity/${dest}" ".known" "true" 30; then
    pass_test "${name}->A: ${name} recalls A's identity"
  else
    fail_test "${name}->A: ${name} recalls A's identity"
    return
  fi

  local resp link_id state
  resp=$(py_link "$py_port" "$dest" "$aspect" || true)
  link_id=$(echo "$resp" | jq -r '.link_id // empty' 2>/dev/null || true)
  state=$(echo "$resp" | jq -r '.state // empty' 2>/dev/null || true)
  echo "  link: ${resp}"
  if [[ "$state" != "active" ]]; then
    fail_test "${name}->A: link active on ${name}" "response: ${resp}"
    return
  fi
  pass_test "${name}->A: link active on ${name}"
  check_rns_link_active "$PORT_A" "$link_id" "${name}->A: link active on A"

  local payload delivered
  payload=$(b64 "packet from ${name} to A")
  resp=$(py_send "$py_port" "$link_id" "$payload" || true)
  delivered=$(echo "$resp" | jq -r '.delivered' 2>/dev/null || true)
  assert_eq "$delivered" "true" "${name}->A: link packet proved by A"

  payload=$(b64 "resource from ${name} to A over a shared instance link")
  resp=$(py_resource "$py_port" "$link_id" "$payload" || true)
  echo "  resource: ${resp}"
  check_rns_resource "$PORT_A" "$link_id" "$payload" \
    "${name}->A: resource data arrived on A"
}

# rns_to_py PY_PORT PY_NAME — rns-rs client A links to the Python node's
# destination and sends a packet over the link.
rns_to_py() {
  local py_port="$1" name="$2"
  echo ""
  echo "--- rns-rs client A -> ${name} ---"

  local dest
  dest=$(py_post "$py_port" "/announce" | jq -r '.dest_hash' || true)
  if [[ -z "$dest" || "$dest" == "null" ]]; then
    fail_test "A->${name}: announce on ${name}"
    return
  fi
  echo "  ${name} destination: ${dest}"

  if poll_until "$PORT_A" "/api/identity/${dest}" ".dest_hash" "$dest" 30; then
    pass_test "A->${name}: A recalls ${name}'s identity"
  else
    fail_test "A->${name}: A recalls ${name}'s identity"
    return
  fi

  local link_id
  link_id=$(create_link "$PORT_A" "$dest" || true)
  if [[ -z "$link_id" || "$link_id" == "null" ]]; then
    fail_test "A->${name}: create link on A"
    return
  fi
  echo "  link: ${link_id}"
  check_rns_link_active "$PORT_A" "$link_id" "A->${name}: link active on A"
  check_py_event "$py_port" "link_established" "$link_id" "" \
    "A->${name}: link established on ${name}"

  local payload
  payload=$(b64 "packet from A to ${name}")
  send_on_link "$PORT_A" "$link_id" "$payload" >/dev/null || true
  check_py_event "$py_port" "packet" "$link_id" "$payload" \
    "A->${name}: link packet data arrived on ${name}"
}

# py_ext_to_py_sib — py-external links to py-sibling through the daemon.
py_ext_to_py_sib() {
  local dest resp link_id state payload delivered
  dest=$(ctl_get "$PORT_PY_SIB" "/info" | jq -r '.dest_hash' || true)
  py_post "$PORT_PY_SIB" "/announce" >/dev/null || true
  if poll_until "$PORT_PY_EXT" "/identity/${dest}" ".known" "true" 30; then
    pass_test "py-external->py-sibling: identity recalled"
    resp=$(py_link "$PORT_PY_EXT" "$dest" "node" || true)
    echo "  link: ${resp}"
    link_id=$(echo "$resp" | jq -r '.link_id // empty' 2>/dev/null || true)
    state=$(echo "$resp" | jq -r '.state // empty' 2>/dev/null || true)
    if [[ "$state" == "active" ]]; then
      pass_test "py-external->py-sibling: link active on py-external"
      check_py_event "$PORT_PY_SIB" "link_established" "$link_id" "" \
        "py-external->py-sibling: link established on py-sibling"
      payload=$(b64 "packet from py-external to py-sibling")
      delivered=$(py_send "$PORT_PY_EXT" "$link_id" "$payload" | jq -r '.delivered' || true)
      assert_eq "$delivered" "true" "py-external->py-sibling: link packet proved"
      check_py_event "$PORT_PY_SIB" "packet" "$link_id" "$payload" \
        "py-external->py-sibling: link packet data arrived"
    else
      fail_test "py-external->py-sibling: link active on py-external" "response: ${resp}"
    fi
  else
    fail_test "py-external->py-sibling: identity recalled"
  fi
}

# ── Step 1: Wait for all nodes ──────────────────────────────────────────────

echo "  Waiting for all endpoints to be healthy..."
for entry in "A:${PORT_A}" "B:${PORT_B}" "py-sibling:${PORT_PY_SIB}" "py-external:${PORT_PY_EXT}"; do
  name="${entry%%:*}"
  port="${entry##*:}"
  if poll_until "$port" "/health" ".status" "healthy" 90; then
    pass_test "${name} healthy"
  else
    fail_test "${name} healthy"
    suite_result "$_CURRENT_SUITE" || true
    exit 1
  fi
done

for entry in "A:${PORT_A}" "B:${PORT_B}"; do
  name="${entry%%:*}"
  port="${entry##*:}"
  if poll_until "$port" "/api/interfaces" \
    '[.interfaces[] | select(.status == "up")] | length > 0' "true" 60; then
    pass_test "${name} attached to the shared instance"
  else
    fail_test "${name} attached to the shared instance"
  fi
done

sib_attached=$(ctl_get "$PORT_PY_SIB" "/info" | jq -r '.connected_to_shared_instance' || true)
assert_eq "$sib_attached" "true" "py-sibling attached to the shared instance"

# Let interfaces settle
sleep 3

# ── Step 2: rns-rs sibling link B -> A ──────────────────────────────────────

echo ""
echo "--- rns-rs client B -> rns-rs client A ---"
if result=$(establish_link "$PORT_B" "$PORT_A" "$APP" "sibling" 30); then
  read -r SIB_LINK SIB_DEST <<<"$result"
  echo "  link ${SIB_LINK} to ${SIB_DEST}"
  pass_test "B->A: link active on B"
  check_rns_link_active "$PORT_A" "$SIB_LINK" "B->A: link active on A"

  is_init=$(get_links "$PORT_B" | jq -r ".links[] | select(.link_id == \"${SIB_LINK}\") | .is_initiator" || true)
  assert_eq "$is_init" "true" "B->A: B is initiator"

  status=$(send_on_link "$PORT_B" "$SIB_LINK" "$(b64 'plain packet from B to A')" | jq -r '.status' || true)
  assert_eq "$status" "sent" "B->A: link packet sent"

  CHAN_DATA=$(b64 "channel message from B to A")
  send_channel "$PORT_B" "$SIB_LINK" 1 "$CHAN_DATA" >/dev/null || true
  if poll_until "$PORT_A" "/api/packets" \
    "[.packets[] | select(.dest_hash == \"channel:${SIB_LINK}:1\" and .data_base64 == \"${CHAN_DATA}\")] | length > 0" \
    "true" 30; then
    pass_test "B->A: channel message arrived on A"
  else
    fail_test "B->A: channel message arrived on A"
  fi

  RES_DATA=$(b64 "resource from B to A over a sibling link")
  send_resource "$PORT_B" "$SIB_LINK" "$RES_DATA" >/dev/null || true
  check_rns_resource "$PORT_A" "$SIB_LINK" "$RES_DATA" "B->A: resource data arrived on A"

  close_link "$PORT_B" "$SIB_LINK" >/dev/null || true
  if poll_until "$PORT_B" "/api/links" \
    "[.links[] | select(.link_id == \"${SIB_LINK}\")] | length" "0" 30; then
    pass_test "B->A: link removed from B after close"
  else
    fail_test "B->A: link removed from B after close"
  fi
  if poll_until "$PORT_A" "/api/links" \
    "[.links[] | select(.link_id == \"${SIB_LINK}\")] | length" "0" 30; then
    pass_test "B->A: link removed from A after close"
  else
    fail_test "B->A: link removed from A after close"
  fi
else
  fail_test "B->A: link active on B"
fi

# ── Steps 3-6: Python sibling / external <-> rns-rs client A ────────────────

py_to_rns "$PORT_PY_SIB" "py-sibling" "pysib"
rns_to_py "$PORT_PY_SIB" "py-sibling"
if external_discovery_supported; then
  py_to_rns "$PORT_PY_EXT" "py-external" "pyext"
else
  skip_step "py-external->A: no path discovery through a non-transport shared instance"
fi
rns_to_py "$PORT_PY_EXT" "py-external"

# ── Step 7: Python external -> Python sibling ───────────────────────────────

echo ""
echo "--- py-external -> py-sibling ---"
if ! external_discovery_supported; then
  skip_step "py-external->py-sibling: no path discovery through a non-transport shared instance"
else
  py_ext_to_py_sib
fi

# ── Step 8: Single DATA packet with proof B -> A ────────────────────────────

echo ""
echo "--- rns-rs client B -> rns-rs client A (single packet) ---"
DEST_DGRAM=$(create_destination "$PORT_A" "single" "$APP" "datagram" "all" || true)
announce "$PORT_A" "$DEST_DGRAM" || true
if poll_until "$PORT_B" "/api/identity/${DEST_DGRAM}" ".dest_hash" "$DEST_DGRAM" 30; then
  OUT_DGRAM=$(create_outbound_dest "$PORT_B" "$APP" "datagram" "$DEST_DGRAM" || true)
  PACKET_HASH=$(send_packet "$PORT_B" "$OUT_DGRAM" "$(b64 'single packet from B to A')" \
    | jq -r '.packet_hash' || true)
  echo "  packet ${PACKET_HASH}"
  if poll_until "$PORT_A" "/api/packets" \
    ".packets[] | select(.packet_hash == \"${PACKET_HASH}\") | .dest_hash" \
    "$DEST_DGRAM" 30; then
    pass_test "B->A single: packet delivered to A"
  else
    fail_test "B->A single: packet delivered to A"
  fi
  if poll_until "$PORT_B" "/api/proofs" \
    ".proofs[] | select(.packet_hash == \"${PACKET_HASH}\") | .packet_hash" \
    "$PACKET_HASH" 30; then
    pass_test "B->A single: proof received on B"
  else
    fail_test "B->A single: proof received on B"
  fi
else
  fail_test "B->A single: B recalls A's identity"
fi

suite_result "$_CURRENT_SUITE"
