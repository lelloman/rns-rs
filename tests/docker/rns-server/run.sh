#!/usr/bin/env bash
# run.sh — Build and run rns-server E2E tests
#
# Tests rns-server process supervision, control APIs, and config management.
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
  docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
  echo "Done."
  exit 0
fi

# ── Build Docker image ──────────────────────────────────────────────────────
# Always build: rns-server-test is a separate image from rns-test,
# so SKIP_BUILD from run-all.sh does not apply.

echo "=== Building rns-server-test Docker image ==="
docker build -t rns-server-test -f "${SCRIPT_DIR}/Dockerfile.rns-server" "$REPO_ROOT"

# ── Set up results file ─────────────────────────────────────────────────────

export TEST_RESULTS_FILE
TEST_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/rns-server-test-results.XXXXXX")"
trap 'rm -f "$TEST_RESULTS_FILE"' EXIT
export TOPOLOGY="rns-server"

# ── Start containers ────────────────────────────────────────────────────────

echo ""
echo "=== Starting rns-server test container ==="
COMPOSE_EXIT=0
docker compose -f "$COMPOSE_FILE" up -d --wait || COMPOSE_EXIT=$?

if [[ $COMPOSE_EXIT -ne 0 ]]; then
  echo ""
  echo "=== Container failed to start (exit $COMPOSE_EXIT) ==="
  echo "=== Container logs ==="
  docker compose -f "$COMPOSE_FILE" logs --tail=200
  echo "=== End logs ==="
fi

# ── Run test ────────────────────────────────────────────────────────────────

TEST_EXIT=0
if [[ $COMPOSE_EXIT -eq 0 ]]; then
  echo ""
  echo "=== Running rns-server E2E tests ==="
  bash "${SCRIPT_DIR}/test.sh" || TEST_EXIT=$?
else
  TEST_EXIT=$COMPOSE_EXIT
fi

# ── Dump logs on failure ────────────────────────────────────────────────────

if [[ $TEST_EXIT -ne 0 && $COMPOSE_EXIT -eq 0 ]]; then
  echo ""
  echo "=== Container logs (last 200 lines) ==="
  docker compose -f "$COMPOSE_FILE" logs --tail=200
  echo "=== End logs ==="
fi

# ── Tear down ───────────────────────────────────────────────────────────────

if ! $NO_TEARDOWN; then
  echo ""
  echo "=== Tearing down containers ==="
  docker compose -f "$COMPOSE_FILE" down -v
fi

exit $TEST_EXIT
