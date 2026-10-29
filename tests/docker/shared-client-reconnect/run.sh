#!/usr/bin/env bash
# run.sh — Build and run shared client reconnection E2E test
#
# This test surfaces GitHub issue #3:
# LocalClientInterface does not reconnect when rnsd restarts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# ── Prerequisites check ─────────────────────────────────────────────────────

for cmd in docker curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not found." >&2
    exit 1
  fi
done

if ! docker compose version &>/dev/null; then
  echo "ERROR: 'docker compose' (v2) is required." >&2
  exit 1
fi

# ── Parse args ──────────────────────────────────────────────────────────────

NO_TEARDOWN=false
CLEAN_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-teardown) NO_TEARDOWN=true; shift ;;
    --clean)       CLEAN_ONLY=true; shift ;;
    *)
      echo "Usage: $0 [--no-teardown] [--clean]" >&2
      exit 1
      ;;
  esac
done

COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

if $CLEAN_ONLY; then
  echo "Cleaning up..."
  docker compose -f "$COMPOSE_FILE" down -v -t "${COMPOSE_STOP_TIMEOUT:-2}" 2>/dev/null || true
  echo "Done."
  exit 0
fi

# ── Build Docker image (skip if already built, e.g. from run-all.sh) ────────

if [[ "${SKIP_BUILD:-}" != "true" ]]; then
  echo "=== Building rns-test Docker image ==="
  docker build --build-arg CARGO_BUILD_JOBS --build-arg CARGO_PROFILE_RELEASE_CODEGEN_UNITS -t rns-test -f "${REPO_ROOT}/tests/docker/Dockerfile" "$REPO_ROOT"
fi

# ── Set up results file ─────────────────────────────────────────────────────

export TEST_RESULTS_FILE
TEST_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/rns-shared-reconnect-results.XXXXXX")"
trap 'rm -f "$TEST_RESULTS_FILE"' EXIT
export TOPOLOGY="shared-client-reconnect"

# ── Start containers ────────────────────────────────────────────────────────

echo ""
echo "=== Starting shared client reconnection topology ==="
docker compose -f "$COMPOSE_FILE" up -d --wait

# ── Run test ────────────────────────────────────────────────────────────────

echo ""
echo "=== Running shared client reconnection test ==="
TEST_EXIT=0
bash "${SCRIPT_DIR}/test.sh" || TEST_EXIT=$?

# ── Dump logs on failure ────────────────────────────────────────────────────

if [[ $TEST_EXIT -ne 0 ]]; then
  echo ""
  echo "=== Container logs (last 200 lines each) ==="
  docker compose -f "$COMPOSE_FILE" logs --tail=200
  echo "=== End logs ==="
fi

# ── Tear down ───────────────────────────────────────────────────────────────

if ! $NO_TEARDOWN; then
  echo ""
  echo "=== Tearing down containers ==="
  docker compose -f "$COMPOSE_FILE" down -v -t "${COMPOSE_STOP_TIMEOUT:-2}"
fi

exit $TEST_EXIT
