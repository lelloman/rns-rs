#!/usr/bin/env bash
# Suite 01: Health — verify all nodes respond 200 on /health
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/helpers.sh"

_CURRENT_SUITE="01_health"
echo "Suite 01: Health check for all nodes"

# Read all port variables from the environment
for var in $(env | grep '_PORT=' | sort); do
  name="${var%%=*}"
  port="${var#*=}"
  status=$(curl -sf -o /dev/null -w "%{http_code}" "http://localhost:${port}/health" 2>/dev/null) || status="000"
  assert_eq "$status" "200" "${name} (port ${port}) health check"
done

suite_result "01_health"
