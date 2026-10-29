#!/usr/bin/env bash
# run.sh — Build and run the shared instance links E2E test
#
# Covers the fix for GitHub issue #183: a shared instance daemon
# (share_instance=Yes, enable_transport=False) dropped HEADER_1 packets
# addressed to destinations behind its local clients, breaking links
# between sibling clients and from directly adjacent Python peers.
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
      echo "  DAEMON_ENABLE_TRANSPORT=False|True runs a single daemon mode" >&2
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

# The Python Reticulum image is always built: SKIP_BUILD only refers to
# rns-test. Docker layer caching makes this cheap after the first run.
echo "=== Building Python Reticulum image (rns==${RNS_VERSION:-1.5.7}) ==="
docker compose -f "$COMPOSE_FILE" build

# ── Set up results file ─────────────────────────────────────────────────────

export TEST_RESULTS_FILE
TEST_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/rns-shared-instance-links-results.XXXXXX")"
trap 'rm -f "$TEST_RESULTS_FILE"' EXIT
export TOPOLOGY="shared-instance-links"

# ── Run one pass per daemon transport mode ──────────────────────────────────
#
# False is the common desktop rnsd setup and the configuration broken by
# issue #183; True covers the same paths on a transport-enabled daemon.
# Set DAEMON_ENABLE_TRANSPORT to run a single mode.

if [[ -n "${DAEMON_ENABLE_TRANSPORT:-}" ]]; then
  MODES=("$DAEMON_ENABLE_TRANSPORT")
else
  MODES=(False True)
fi

TEST_EXIT=0
for i in "${!MODES[@]}"; do
  mode="${MODES[$i]}"
  export DAEMON_ENABLE_TRANSPORT="$mode"

  echo ""
  echo "=== Starting shared instance links topology (enable_transport=${mode}) ==="
  docker compose -f "$COMPOSE_FILE" up -d --wait

  echo ""
  echo "=== Running shared instance links test (enable_transport=${mode}) ==="
  PASS_EXIT=0
  bash "${SCRIPT_DIR}/test.sh" || PASS_EXIT=$?

  if [[ $PASS_EXIT -ne 0 ]]; then
    TEST_EXIT=$PASS_EXIT
    echo ""
    echo "=== Container logs (last 200 lines each) ==="
    docker compose -f "$COMPOSE_FILE" logs --tail=200
    echo "=== End logs ==="
  fi

  # Always tear down between passes; honour --no-teardown after the last.
  if (( i < ${#MODES[@]} - 1 )) || ! $NO_TEARDOWN; then
    echo ""
    echo "=== Tearing down containers ==="
    docker compose -f "$COMPOSE_FILE" down -v -t "${COMPOSE_STOP_TIMEOUT:-2}"
  fi
done

exit $TEST_EXIT
