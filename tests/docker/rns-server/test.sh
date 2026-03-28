#!/usr/bin/env bash
# test.sh — rns-server E2E tests
#
# Tests process supervision, control APIs, and config management.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/helpers.sh"

_CURRENT_SUITE="rns-server"

PORT=8090

echo "=== rns-server E2E Tests ==="

# ── Section 1: Health and server mode ────────────────────────────────────────

echo ""
echo "--- Section 1: Health and server mode ---"

if poll_until "$PORT" "/health" ".status" "healthy" 30; then
  pass_test "health endpoint returns healthy"
else
  fail_test "health endpoint returns healthy"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi

NODE_RESP=$(ctl_get "$PORT" "/api/node" 2>/dev/null || echo "{}")
SERVER_MODE=$(echo "$NODE_RESP" | jq -r '.server_mode // empty')
assert_eq "$SERVER_MODE" "supervised" "server_mode is supervised"

# uptime_seconds is a float; truncate to integer for comparison
UPTIME=$(echo "$NODE_RESP" | jq -r '.uptime_seconds // 0 | floor | tostring')
assert_ge "$UPTIME" "1" "uptime >= 1s"

# ── Section 2: All 3 processes started and ready ─────────────────────────────

echo ""
echo "--- Section 2: Process startup and readiness ---"

# Poll until all 3 processes are running
if poll_until "$PORT" "/api/processes" \
  '[.processes[] | select(.status == "running")] | length | tostring' \
  "3" 30; then
  pass_test "all 3 processes running"
else
  fail_test "all 3 processes running"
  PROC_STATUS=$(ctl_get "$PORT" "/api/processes" 2>/dev/null || echo "{}")
  echo "  Process status: $PROC_STATUS"
fi

# Poll until all 3 are ready (hook-based readiness may take longer)
if poll_until "$PORT" "/api/processes" \
  '[.processes[] | select(.ready == true)] | length | tostring' \
  "3" 60; then
  pass_test "all 3 processes ready"
else
  fail_test "all 3 processes ready"
  PROC_STATUS=$(ctl_get "$PORT" "/api/processes" 2>/dev/null || echo "{}")
  echo "  Process status: $PROC_STATUS"
fi

# Verify each process individually
for proc_name in rnsd rns-sentineld rns-statsd; do
  PROC_STATUS=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
    | jq -r ".processes[] | select(.name == \"${proc_name}\") | .status" || echo "")
  assert_eq "$PROC_STATUS" "running" "${proc_name} status is running"

  PROC_PID=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
    | jq -r ".processes[] | select(.name == \"${proc_name}\") | .pid // empty" || echo "")
  assert_ne "$PROC_PID" "" "${proc_name} has a pid"
done

# ── Section 3: Process logs ──────────────────────────────────────────────────

echo ""
echo "--- Section 3: Process logs ---"

for proc_name in rnsd rns-sentineld rns-statsd; do
  LOG_COUNT=$(ctl_get "$PORT" "/api/processes/${proc_name}/logs" 2>/dev/null \
    | jq '.lines | length' 2>/dev/null || echo "0")
  assert_gt "$LOG_COUNT" "0" "${proc_name} has log lines"
done

# ── Section 4: Process events ────────────────────────────────────────────────

echo ""
echo "--- Section 4: Process events ---"

EVENT_COUNT=$(ctl_get "$PORT" "/api/process_events" 2>/dev/null \
  | jq '.events | length' 2>/dev/null || echo "0")
assert_ge "$EVENT_COUNT" "3" "at least 3 process events recorded"

# Readiness probes emit "ready" events for each process once they come up
for proc_name in rnsd rns-sentineld rns-statsd; do
  HAS_READY=$(ctl_get "$PORT" "/api/process_events" 2>/dev/null \
    | jq "[.events[] | select(.process == \"${proc_name}\" and .event == \"ready\")] | length" \
    2>/dev/null || echo "0")
  assert_ge "$HAS_READY" "1" "${proc_name} has a ready event"
done

# ── Section 5: Stop a process ────────────────────────────────────────────────

echo ""
echo "--- Section 5: Stop a process ---"

ctl_post "$PORT" "/api/processes/rns-statsd/stop" > /dev/null 2>&1

if poll_until "$PORT" "/api/processes" \
  '.processes[] | select(.name == "rns-statsd") | .status' \
  "stopped" 15; then
  pass_test "rns-statsd stopped"
else
  fail_test "rns-statsd stopped"
fi

# Other processes still running
RUNNING_COUNT=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
  | jq '[.processes[] | select(.status == "running")] | length' 2>/dev/null || echo "0")
assert_eq "$RUNNING_COUNT" "2" "2 processes still running after stop"

# Server still responsive
if poll_until "$PORT" "/health" ".status" "healthy" 5; then
  pass_test "server still healthy after stopping rns-statsd"
else
  fail_test "server still healthy after stopping rns-statsd"
fi

# ── Section 6: Start a stopped process ───────────────────────────────────────

echo ""
echo "--- Section 6: Start a stopped process ---"

ctl_post "$PORT" "/api/processes/rns-statsd/start" > /dev/null 2>&1

if poll_until "$PORT" "/api/processes" \
  '.processes[] | select(.name == "rns-statsd") | .status' \
  "running" 15; then
  pass_test "rns-statsd started after stop"
else
  fail_test "rns-statsd started after stop"
fi

# All 3 running again
if poll_until "$PORT" "/api/processes" \
  '[.processes[] | select(.status == "running")] | length | tostring' \
  "3" 15; then
  pass_test "all 3 processes running after start"
else
  fail_test "all 3 processes running after start"
fi

# ── Section 7: Restart a process ─────────────────────────────────────────────
# Restart rns-statsd (not rnsd — restarting rnsd kills the provider bridge
# socket, which causes rns-sentineld to exit and triggers full shutdown)

echo ""
echo "--- Section 7: Restart a process ---"

# Record current rns-statsd pid
OLD_PID=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
  | jq -r '.processes[] | select(.name == "rns-statsd") | .pid' || echo "")
echo "  rns-statsd pid before restart: ${OLD_PID}"

ctl_post "$PORT" "/api/processes/rns-statsd/restart" > /dev/null 2>&1

# Poll until pid changes
DEADLINE=$((SECONDS + 30))
NEW_PID="$OLD_PID"
while (( SECONDS < DEADLINE )); do
  NEW_PID=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
    | jq -r '.processes[] | select(.name == "rns-statsd") | .pid // empty' || echo "")
  if [[ -n "$NEW_PID" && "$NEW_PID" != "null" && "$NEW_PID" != "$OLD_PID" ]]; then
    break
  fi
  sleep 1
done

echo "  rns-statsd pid after restart: ${NEW_PID}"
assert_ne "$NEW_PID" "$OLD_PID" "rns-statsd pid changed after restart"

# Verify restart count increased
RESTART_COUNT=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
  | jq -r '.processes[] | select(.name == "rns-statsd") | .restart_count' || echo "0")
assert_ge "$RESTART_COUNT" "1" "rns-statsd restart_count >= 1"

# Wait for rns-statsd to become ready again
if poll_until "$PORT" "/api/processes" \
  '.processes[] | select(.name == "rns-statsd") | .ready | tostring' \
  "true" 30; then
  pass_test "rns-statsd ready after restart"
else
  fail_test "rns-statsd ready after restart"
fi

# ── Section 8: Config read ───────────────────────────────────────────────────

echo ""
echo "--- Section 8: Config read ---"

CONFIG_RESP=$(ctl_get "$PORT" "/api/config" 2>/dev/null || echo "{}")

LAUNCH_PLAN_LEN=$(echo "$CONFIG_RESP" | jq '.config.launch_plan | length' 2>/dev/null || echo "0")
assert_eq "$LAUNCH_PLAN_LEN" "3" "launch_plan has 3 entries"

HTTP_ENABLED=$(echo "$CONFIG_RESP" | jq -r '.config.http.enabled' 2>/dev/null || echo "")
assert_eq "$HTTP_ENABLED" "true" "http.enabled is true"

# ── Section 9: Config validate ───────────────────────────────────────────────

echo ""
echo "--- Section 9: Config validate ---"

VALIDATE_RESP=$(ctl_post "$PORT" "/api/config/validate" '{"http": {"port": 9090}}' 2>/dev/null || echo "{}")
VALID=$(echo "$VALIDATE_RESP" | jq -r '.result.valid' 2>/dev/null || echo "")
assert_eq "$VALID" "true" "valid config validates successfully"

# Invalid JSON should return error (curl -sf fails on non-2xx, so we check exit code)
if curl -sf -X POST -H "Content-Type: application/json" \
  -d 'not valid json' "http://localhost:${PORT}/api/config/validate" > /dev/null 2>&1; then
  fail_test "invalid JSON rejected" "server accepted invalid JSON"
else
  pass_test "invalid JSON rejected"
fi

# ── Section 10: Config save ──────────────────────────────────────────────────

echo ""
echo "--- Section 10: Config save ---"

# Save a config that matches the running HTTP settings to avoid triggering
# a control-plane restart notification. Only set stats_db_path to the current
# value so there are no process-affecting changes.
SAVE_RESP=$(ctl_post "$PORT" "/api/config" \
  '{"http": {"host": "0.0.0.0", "port": 8080, "disable_auth": true}}' 2>/dev/null || echo "{}")
SAVE_ACTION=$(echo "$SAVE_RESP" | jq -r '.result.action' 2>/dev/null || echo "")
assert_eq "$SAVE_ACTION" "save" "config save returns action=save"

# Server still responsive after save (no restart)
if poll_until "$PORT" "/health" ".status" "healthy" 5; then
  pass_test "server healthy after config save"
else
  fail_test "server healthy after config save"
fi

# Config status endpoint works
CONFIG_STATUS=$(ctl_get "$PORT" "/api/config/status" 2>/dev/null || echo "{}")
HAS_STATUS=$(echo "$CONFIG_STATUS" | jq 'has("status")' 2>/dev/null || echo "false")
assert_eq "$HAS_STATUS" "true" "config/status returns status object"

# ── Section 11: Config apply ─────────────────────────────────────────────────

echo ""
echo "--- Section 11: Config apply ---"

# Record current rns-statsd restart count before apply
STATSD_RESTARTS_BEFORE=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
  | jq -r '.processes[] | select(.name == "rns-statsd") | .restart_count' || echo "0")

# Apply a config change that affects rns-statsd (different stats_db_path)
# Keep HTTP settings matching the running config to avoid control-plane issues
APPLY_RESP=$(ctl_post "$PORT" "/api/config/apply" \
  '{"stats_db_path": "/data/stats-new.db", "http": {"host": "0.0.0.0", "port": 8080, "disable_auth": true}}' \
  2>/dev/null || echo "{}")
APPLY_ACTION=$(echo "$APPLY_RESP" | jq -r '.result.action' 2>/dev/null || echo "")
assert_eq "$APPLY_ACTION" "apply" "config apply returns action=apply"

# The apply should plan to restart rns-statsd (stats_db_path changed)
RESTART_PLANNED=$(echo "$APPLY_RESP" | jq -r '.result.apply_plan.processes_to_restart | length' 2>/dev/null || echo "0")
assert_gt "$RESTART_PLANNED" "0" "apply plan includes process restarts"

# Poll for rns-statsd restart count to increase
DEADLINE=$((SECONDS + 15))
STATSD_RESTARTS_AFTER="$STATSD_RESTARTS_BEFORE"
while (( SECONDS < DEADLINE )); do
  STATSD_RESTARTS_AFTER=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
    | jq -r '.processes[] | select(.name == "rns-statsd") | .restart_count' || echo "0")
  if (( STATSD_RESTARTS_AFTER > STATSD_RESTARTS_BEFORE )); then
    break
  fi
  sleep 1
done
assert_gt "$STATSD_RESTARTS_AFTER" "$STATSD_RESTARTS_BEFORE" "rns-statsd restarted after config apply"

# All processes running and healthy after apply
if poll_until "$PORT" "/api/processes" \
  '[.processes[] | select(.status == "running")] | length | tostring' \
  "3" 30; then
  pass_test "all 3 processes running after config apply"
else
  fail_test "all 3 processes running after config apply"
fi

# ── Results ──────────────────────────────────────────────────────────────────

suite_result "$_CURRENT_SUITE"
