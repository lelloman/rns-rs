#!/usr/bin/env bash
# helpers.sh — shared functions for Docker E2E test suites
set -euo pipefail

PASSES=0
FAILURES=0
_CURRENT_SUITE=""

# ── Result recording ─────────────────────────────────────────────────────────
# When TEST_RESULTS_FILE is set (by run.sh / run-all.sh), every assertion,
# pass_test, fail_test and skip_suite appends a tab-delimited line:
#   STATUS \t TOPOLOGY \t SUITE \t MESSAGE \t DETAIL

record_result() {
  local status="$1" msg="$2" detail="${3:-}"
  if [[ -n "${TEST_RESULTS_FILE:-}" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$status" "${TOPOLOGY:-unknown}" "${_CURRENT_SUITE:-unknown}" "$msg" "$detail" \
      >> "$TEST_RESULTS_FILE"
  fi
}

pass_test() {
  local msg="$1"
  echo "  PASS: ${msg}"
  (( PASSES++ )) || true
  record_result "PASS" "$msg"
}

fail_test() {
  local msg="$1" detail="${2:-}"
  if [[ -n "$detail" ]]; then
    echo "  FAIL: ${msg} — ${detail}"
  else
    echo "  FAIL: ${msg}"
  fi
  (( FAILURES++ )) || true
  record_result "FAIL" "$msg" "$detail"
}

skip_suite() {
  local reason="$1"
  echo "  SKIP: ${reason}"
  record_result "SKIP" "${reason}"
  exit 0
}

# ── HTTP helpers ──────────────────────────────────────────────────────────────

ctl_get() {
  local port="$1" path="$2"
  curl -sf "http://localhost:${port}${path}"
}

ctl_post() {
  local port="$1" path="$2" body="${3:-"{}"}"
  curl -sf -X POST -H "Content-Type: application/json" \
    -d "$body" "http://localhost:${port}${path}"
}

# ── Polling helpers ───────────────────────────────────────────────────────────

# poll_until PORT PATH JQ_FILTER EXPECTED TIMEOUT_SEC
#   Repeatedly GET PORT/PATH, pipe through jq, compare to EXPECTED.
#   Returns 0 on match, 1 on timeout.
poll_until() {
  local port="$1" path="$2" jq_filter="$3" expected="$4" timeout="${5:-30}"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    local result
    result=$(curl -sf "http://localhost:${port}${path}" 2>/dev/null | jq -r "$jq_filter" 2>/dev/null) || true
    if [[ "$result" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT: poll_until ${port}${path} | jq '${jq_filter}' expected '${expected}', last got '${result:-<empty>}'" >&2
  return 1
}

# poll_count PORT PATH JQ_ARRAY_FILTER MIN TIMEOUT_SEC
#   Wait until the jq array expression has >= MIN elements.
poll_count() {
  local port="$1" path="$2" jq_filter="$3" min="$4" timeout="${5:-30}"
  local deadline=$((SECONDS + timeout))
  local count=0
  while (( SECONDS < deadline )); do
    count=$(curl -sf "http://localhost:${port}${path}" 2>/dev/null \
      | jq -r "${jq_filter} | length" 2>/dev/null) || true
    if [[ -n "$count" ]] && (( count >= min )); then
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT: poll_count ${port}${path} | jq '${jq_filter} | length' expected >= ${min}, last got ${count:-0}" >&2
  return 1
}

# ── Assertions ────────────────────────────────────────────────────────────────

assert_eq() {
  local actual="$1" expected="$2" msg="${3:-assert_eq}"
  if [[ "$actual" == "$expected" ]]; then
    pass_test "$msg"
  else
    fail_test "$msg" "expected '${expected}', got '${actual}'"
  fi
}

assert_ne() {
  local actual="$1" unexpected="$2" msg="${3:-assert_ne}"
  if [[ "$actual" != "$unexpected" ]]; then
    pass_test "$msg"
  else
    fail_test "$msg" "expected != '${unexpected}', got '${actual}'"
  fi
}

assert_ge() {
  local actual="$1" minimum="$2" msg="${3:-assert_ge}"
  if (( actual >= minimum )); then
    pass_test "$msg"
  else
    fail_test "$msg" "expected >= ${minimum}, got ${actual}"
  fi
}

assert_gt() {
  local actual="$1" threshold="$2" msg="${3:-assert_gt}"
  if (( actual > threshold )); then
    pass_test "$msg"
  else
    fail_test "$msg" "expected > ${threshold}, got ${actual}"
  fi
}

assert_le() {
  local actual="$1" maximum="$2" msg="${3:-assert_le}"
  if (( actual <= maximum )); then
    pass_test "$msg"
  else
    fail_test "$msg" "expected <= ${maximum}, got ${actual}"
  fi
}

# ── Destination helpers ───────────────────────────────────────────────────────

# create_destination PORT TYPE APP ASPECTS [PROOF_STRATEGY]
#   Creates an inbound destination. Echoes dest_hash.
create_destination() {
  local port="$1" dtype="$2" app="$3" aspects="$4" proof="${5:-none}"
  local aspects_json
  aspects_json=$(echo "$aspects" | jq -R 'split(",")')
  local body
  body=$(jq -n \
    --arg type "$dtype" \
    --arg app "$app" \
    --argjson aspects "$aspects_json" \
    --arg proof "$proof" \
    '{type: $type, app_name: $app, aspects: $aspects, direction: "in", proof_strategy: $proof}')
  ctl_post "$port" "/api/destination" "$body" | jq -r '.dest_hash'
}

# create_outbound_dest PORT APP ASPECTS REMOTE_HASH
#   Creates an outbound single destination. Echoes dest_hash.
create_outbound_dest() {
  local port="$1" app="$2" aspects="$3" remote_hash="$4"
  local aspects_json
  aspects_json=$(echo "$aspects" | jq -R 'split(",")')
  local body
  body=$(jq -n \
    --arg app "$app" \
    --argjson aspects "$aspects_json" \
    --arg dest "$remote_hash" \
    '{type: "single", app_name: $app, aspects: $aspects, direction: "out", dest_hash: $dest}')
  ctl_post "$port" "/api/destination" "$body" | jq -r '.dest_hash'
}

# announce PORT DEST_HASH [APP_DATA_B64]
announce() {
  local port="$1" dest_hash="$2" app_data="${3:-}"
  local body
  if [[ -n "$app_data" ]]; then
    body=$(jq -n --arg dh "$dest_hash" --arg ad "$app_data" \
      '{dest_hash: $dh, app_data: $ad}')
  else
    body=$(jq -n --arg dh "$dest_hash" '{dest_hash: $dh}')
  fi
  ctl_post "$port" "/api/announce" "$body" > /dev/null
}

# ── Send/query helpers ────────────────────────────────────────────────────────

send_packet() {
  local port="$1" dest_hash="$2" data_b64="$3"
  local body
  body=$(jq -n --arg dh "$dest_hash" --arg d "$data_b64" \
    '{dest_hash: $dh, data: $d}')
  ctl_post "$port" "/api/send" "$body"
}

get_announces() {
  local port="$1"
  ctl_get "$port" "/api/announces"
}

get_packets() {
  local port="$1"
  ctl_get "$port" "/api/packets"
}

get_proofs() {
  local port="$1"
  ctl_get "$port" "/api/proofs"
}

get_paths() {
  local port="$1" dest_hash="${2:-}"
  if [[ -n "$dest_hash" ]]; then
    ctl_get "$port" "/api/paths?dest_hash=${dest_hash}"
  else
    ctl_get "$port" "/api/paths"
  fi
}

get_identity() {
  local port="$1" dest_hash="$2"
  ctl_get "$port" "/api/identity/${dest_hash}"
}

# ── Test reporting ────────────────────────────────────────────────────────────

suite_result() {
  local name="$1"
  echo ""
  echo "=== ${name}: ${PASSES} passed, ${FAILURES} failed ==="
  if (( FAILURES > 0 )); then
    return 1
  fi
  return 0
}
