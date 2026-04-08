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

  READY_STATE=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
    | jq -r ".processes[] | select(.name == \"${proc_name}\") | .ready_state // empty" || echo "")
  assert_eq "$READY_STATE" "ready" "${proc_name} ready_state is ready"

  PROC_PID=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
    | jq -r ".processes[] | select(.name == \"${proc_name}\") | .pid // empty" || echo "")
  assert_ne "$PROC_PID" "" "${proc_name} has a pid"
done

# ── Section 3: Process logs ──────────────────────────────────────────────────

echo ""
echo "--- Section 3: Process logs ---"

for proc_name in rnsd rns-sentineld rns-statsd; do
  PROCESS_JSON=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
    | jq ".processes[] | select(.name == \"${proc_name}\")" 2>/dev/null || echo "{}")
  LOG_PATH=$(echo "$PROCESS_JSON" | jq -r '.durable_log_path // empty' 2>/dev/null || echo "")
  assert_ne "$LOG_PATH" "" "${proc_name} exposes durable_log_path"

  if docker exec rns-server-test test -f "$LOG_PATH" >/dev/null 2>&1; then
    pass_test "${proc_name} durable log file exists in container"
  else
    fail_test "${proc_name} durable log file exists in container" "$LOG_PATH"
  fi

  LOG_COUNT=$(ctl_get "$PORT" "/api/processes/${proc_name}/logs" 2>/dev/null \
    | jq '.lines | length' 2>/dev/null || echo "0")
  assert_gt "$LOG_COUNT" "0" "${proc_name} has log lines"

  if docker exec rns-server-test sh -c "grep -q '\\[stdout\\]\\|\\[stderr\\]' '$LOG_PATH'" >/dev/null 2>&1; then
    pass_test "${proc_name} persisted log file contains stream-tagged lines"
  else
    fail_test "${proc_name} persisted log file contains stream-tagged lines" "$LOG_PATH"
  fi
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
# Restart rns-statsd first to verify ordinary sidecar restart behavior.

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

# ── Section 8: Restart rnsd with drain ──────────────────────────────────────

echo ""
echo "--- Section 8: Restart rnsd with drain ---"

OLD_RNSD_PID=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
  | jq -r '.processes[] | select(.name == "rnsd") | .pid' || echo "")
RNSD_RESTARTS_BEFORE=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
  | jq -r '.processes[] | select(.name == "rnsd") | .restart_count' || echo "0")
echo "  rnsd pid before restart: ${OLD_RNSD_PID}"

if ctl_post "$PORT" "/api/processes/rnsd/restart" > /dev/null 2>&1; then
  pass_test "rnsd restart request accepted"
else
  fail_test "rnsd restart request accepted"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi

if poll_count "$PORT" "/api/process_events" \
  '[.events[] | select(.process == "rnsd" and .event == "draining")]' \
  1 20; then
  pass_test "rnsd emits draining event during restart"
else
  fail_test "rnsd emits draining event during restart"
fi

DEADLINE=$((SECONDS + 45))
NEW_RNSD_PID="$OLD_RNSD_PID"
while (( SECONDS < DEADLINE )); do
  NEW_RNSD_PID=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
    | jq -r '.processes[] | select(.name == "rnsd") | .pid // empty' || echo "")
  if [[ -n "$NEW_RNSD_PID" && "$NEW_RNSD_PID" != "null" && "$NEW_RNSD_PID" != "$OLD_RNSD_PID" ]]; then
    break
  fi
  sleep 1
done

echo "  rnsd pid after restart: ${NEW_RNSD_PID}"
assert_ne "$NEW_RNSD_PID" "$OLD_RNSD_PID" "rnsd pid changed after restart"

RNSD_RESTARTS_AFTER=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
  | jq -r '.processes[] | select(.name == "rnsd") | .restart_count' || echo "0")
assert_gt "$RNSD_RESTARTS_AFTER" "$RNSD_RESTARTS_BEFORE" "rnsd restart_count increased"

if poll_until "$PORT" "/api/processes" \
  '.processes[] | select(.name == "rnsd") | .ready_state' \
  "ready" 45; then
  pass_test "rnsd ready after restart"
else
  fail_test "rnsd ready after restart"
fi

if poll_until "$PORT" "/api/processes" \
  '[.processes[] | select(.status == "running")] | length | tostring' \
  "3" 45; then
  pass_test "all 3 processes running after rnsd restart"
else
  fail_test "all 3 processes running after rnsd restart"
fi

if poll_until "$PORT" "/api/processes" \
  '[.processes[] | select(.ready == true)] | length | tostring' \
  "3" 45; then
  pass_test "all 3 processes ready after rnsd restart"
else
  fail_test "all 3 processes ready after rnsd restart"
fi

if poll_until "$PORT" "/api/process_events" \
  '[.events[] | select(.process == "rnsd")] | last | .event' \
  "ready" 20; then
  pass_test "latest rnsd lifecycle event returns to ready after restart"
else
  fail_test "latest rnsd lifecycle event returns to ready after restart"
fi

# ── Section 9: Config read ───────────────────────────────────────────────────

echo ""
echo "--- Section 9: Config read ---"

CONFIG_RESP=$(ctl_get "$PORT" "/api/config" 2>/dev/null || echo "{}")
SCHEMA_RESP=$(ctl_get "$PORT" "/api/config/schema" 2>/dev/null || echo "{}")

LAUNCH_PLAN_LEN=$(echo "$CONFIG_RESP" | jq '.config.launch_plan | length' 2>/dev/null || echo "0")
assert_eq "$LAUNCH_PLAN_LEN" "3" "launch_plan has 3 entries"

HTTP_ENABLED=$(echo "$CONFIG_RESP" | jq -r '.config.http.enabled' 2>/dev/null || echo "")
assert_eq "$HTTP_ENABLED" "true" "http.enabled is true"

SCHEMA_FIELDS=$(echo "$SCHEMA_RESP" | jq '.schema.fields | length' 2>/dev/null || echo "0")
assert_gt "$SCHEMA_FIELDS" "0" "config schema exposes fields"

EXAMPLE_JSON_PRESENT=$(echo "$SCHEMA_RESP" | jq -r '.schema.example_config_json | length > 0' 2>/dev/null || echo "false")
assert_eq "$EXAMPLE_JSON_PRESENT" "true" "config schema includes example JSON"

# ── Section 10: Config validate ──────────────────────────────────────────────

echo ""
echo "--- Section 10: Config validate ---"

VALIDATE_RESP=$(ctl_post "$PORT" "/api/config/validate" '{"http": {"port": 9090}}' 2>/dev/null || echo "{}")
VALID=$(echo "$VALIDATE_RESP" | jq -r '.result.valid' 2>/dev/null || echo "")
assert_eq "$VALID" "true" "valid config validates successfully"

WARNING_VALIDATE_RESP=$(ctl_post "$PORT" "/api/config/validate" \
  '{"http": {"enabled": false, "disable_auth": true, "auth_token": "ignored-token"}}' \
  2>/dev/null || echo "{}")
WARNING_COUNT=$(echo "$WARNING_VALIDATE_RESP" | jq -r '.result.warnings | length' 2>/dev/null || echo "0")
assert_gt "$WARNING_COUNT" "0" "config validation returns warnings for inactive HTTP fields"

# Invalid JSON should return error (curl -sf fails on non-2xx, so we check exit code)
if curl -sf -X POST -H "Content-Type: application/json" \
  -d 'not valid json' "http://localhost:${PORT}/api/config/validate" > /dev/null 2>&1; then
  fail_test "invalid JSON rejected" "server accepted invalid JSON"
else
  pass_test "invalid JSON rejected"
fi

if curl -sf -X POST -H "Content-Type: application/json" \
  -d '{"unknown_field":true}' "http://localhost:${PORT}/api/config/validate" > /dev/null 2>&1; then
  fail_test "unknown config fields rejected" "server accepted unknown config field"
else
  pass_test "unknown config fields rejected"
fi

# ── Section 11: Config save ──────────────────────────────────────────────────

echo ""
echo "--- Section 11: Config save ---"

# Save a config that matches the running HTTP settings to avoid triggering
# a control-plane restart notification. Only set stats_db_path to the current
# value so there are no process-affecting changes.
SAVE_RESP=$(ctl_post "$PORT" "/api/config" \
  '{"http": {"host": "0.0.0.0", "port": 8080, "disable_auth": true}}' 2>/dev/null || echo "{}")
SAVE_ACTION=$(echo "$SAVE_RESP" | jq -r '.result.action' 2>/dev/null || echo "")
assert_eq "$SAVE_ACTION" "save" "config save returns action=save"

SAVE_WARNINGS=$(echo "$SAVE_RESP" | jq -r '.result.warnings | length' 2>/dev/null || echo "0")
assert_eq "$SAVE_WARNINGS" "0" "config save returns no warnings for active HTTP config"

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

# ── Section 12: Config apply ─────────────────────────────────────────────────

echo ""
echo "--- Section 12: Config apply ---"

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
APPLY_OVERALL_ACTION=$(echo "$APPLY_RESP" | jq -r '.result.apply_plan.overall_action // empty' 2>/dev/null || echo "")
assert_eq "$APPLY_OVERALL_ACTION" "restart_children" "config apply overall action is restart_children"

# The apply should plan to restart rns-statsd (stats_db_path changed)
RESTART_PLANNED=$(echo "$APPLY_RESP" | jq -r '.result.apply_plan.processes_to_restart | length' 2>/dev/null || echo "0")
assert_gt "$RESTART_PLANNED" "0" "apply plan includes process restarts"
APPLY_TARGET=$(echo "$APPLY_RESP" | jq -r '.result.apply_plan.processes_to_restart[0] // empty' 2>/dev/null || echo "")
assert_eq "$APPLY_TARGET" "rns-statsd" "apply plan targets rns-statsd"

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

if poll_until "$PORT" "/api/processes" \
  '.processes[] | select(.name == "rns-statsd") | .ready_state' \
  "ready" 30; then
  pass_test "rns-statsd ready_state returns to ready after config apply"
else
  fail_test "rns-statsd ready_state returns to ready after config apply"
fi

if poll_until "$PORT" "/api/config/status" '.status.converged | tostring' "true" 30; then
  pass_test "config status converges after config apply"
else
  fail_test "config status converges after config apply"
fi

PENDING_RESTARTS=$(ctl_get "$PORT" "/api/config/status" 2>/dev/null \
  | jq -r '.status.pending_process_restarts | length' 2>/dev/null || echo "0")
assert_eq "$PENDING_RESTARTS" "0" "no pending process restarts remain after convergence"

POST_APPLY_LOG_PATH=$(ctl_get "$PORT" "/api/processes" 2>/dev/null \
  | jq -r '.processes[] | select(.name == "rns-statsd") | .durable_log_path // empty' 2>/dev/null || echo "")
assert_ne "$POST_APPLY_LOG_PATH" "" "rns-statsd still exposes durable_log_path after apply"

if docker exec rns-server-test test -f "$POST_APPLY_LOG_PATH" >/dev/null 2>&1; then
  pass_test "rns-statsd durable log file persists after apply"
else
  fail_test "rns-statsd durable log file persists after apply" "$POST_APPLY_LOG_PATH"
fi

HAS_RECENT_EVENT=$(ctl_get "$PORT" "/api/process_events" 2>/dev/null \
  | jq '[.events[] | select(.process == "rns-statsd")] | length' \
  2>/dev/null || echo "0")
assert_ge "$HAS_RECENT_EVENT" "1" "rns-statsd records recent lifecycle events after apply"

# ── Results ──────────────────────────────────────────────────────────────────

suite_result "$_CURRENT_SUITE"
