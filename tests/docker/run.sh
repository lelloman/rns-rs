#!/usr/bin/env bash
# run.sh — Docker E2E test runner for rns-rs
# Usage:
#   ./tests/docker/run.sh                              # All suites on chain-3
#   ./tests/docker/run.sh --topology chain-5            # Use chain-5
#   ./tests/docker/run.sh --suite 04                    # Run only suite 04
#   ./tests/docker/run.sh --topology star-30 --suite 10 # Scale test
#   ./tests/docker/run.sh --clean                       # Remove containers + image
#   ./tests/docker/run.sh --no-teardown                 # Keep containers after run
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TOPOLOGY="chain-3"
SUITE_FILTER=""
CLEAN_ONLY=false
NO_TEARDOWN=false

# ── Parse args ────────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --topology) TOPOLOGY="$2"; shift 2 ;;
    --suite)    SUITE_FILTER="$2"; shift 2 ;;
    --clean)    CLEAN_ONLY=true; shift ;;
    --no-teardown) NO_TEARDOWN=true; shift ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [--topology TOPO] [--suite NUM] [--clean] [--no-teardown]" >&2
      exit 1
      ;;
  esac
done

# ── Clean mode ────────────────────────────────────────────────────────────────

if $CLEAN_ONLY; then
  echo "Cleaning up..."
  # Stop any running compositions
  for f in "${SCRIPT_DIR}"/configs/*/docker-compose.yml; do
    if [[ -f "$f" ]]; then
      docker compose -f "$f" down -v 2>/dev/null || true
    fi
  done
  docker rmi rns-test 2>/dev/null || true
  rm -rf "${SCRIPT_DIR}/configs"
  echo "Done."
  exit 0
fi

# ── Prerequisites check ──────────────────────────────────────────────────────

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

# ── Parse topology name ──────────────────────────────────────────────────────

TOPO_TYPE="${TOPOLOGY%%-*}"     # e.g. "chain"
TOPO_N="${TOPOLOGY#*-}"         # e.g. "3"
TOPO_SCRIPT="${SCRIPT_DIR}/topologies/${TOPO_TYPE}.sh"

if [[ ! -f "$TOPO_SCRIPT" ]]; then
  echo "ERROR: Unknown topology type '${TOPO_TYPE}'" >&2
  echo "Available: chain, star, mesh" >&2
  exit 1
fi

COMPOSE_FILE="${SCRIPT_DIR}/configs/${TOPOLOGY}/docker-compose.yml"
PORTS_FILE="${SCRIPT_DIR}/configs/${TOPOLOGY}/ports.env"

# ── Build Docker image ────────────────────────────────────────────────────────

echo "=== Building rns-test Docker image ==="
docker build -t rns-test -f "${SCRIPT_DIR}/Dockerfile" "$REPO_ROOT"

# ── Generate topology ─────────────────────────────────────────────────────────

echo ""
echo "=== Generating topology: ${TOPOLOGY} ==="
bash "$TOPO_SCRIPT" "$TOPO_N"

# ── Start containers ──────────────────────────────────────────────────────────

echo ""
echo "=== Starting containers ==="
docker compose -f "$COMPOSE_FILE" up -d --wait

# Export all variables from ports.env so suites can use them
set -a
source "$PORTS_FILE"
set +a

# Also export topology metadata
export TOPO_TYPE TOPO_N TOPOLOGY

# ── Results file ─────────────────────────────────────────────────────────────

export TEST_RESULTS_FILE
TEST_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/rns-test-results.XXXXXX")"
trap 'rm -f "$TEST_RESULTS_FILE"' EXIT

source "${SCRIPT_DIR}/lib/summary.sh"

# ── Run test suites ───────────────────────────────────────────────────────────

SUITES_RUN=0
SUITES_FAILED=0

run_suite() {
  local suite_file="$1"
  local suite_name
  suite_name="$(basename "$suite_file" .sh)"

  echo ""
  echo "=== Running suite: ${suite_name} ==="

  if bash "$suite_file"; then
    (( SUITES_RUN++ )) || true
  else
    (( SUITES_RUN++ )) || true
    (( SUITES_FAILED++ )) || true
    echo "  Suite ${suite_name} had failures"

    # Dump logs on failure
    echo "--- Container logs (last 50 lines each) ---"
    docker compose -f "$COMPOSE_FILE" logs --tail=50
    echo "--- End logs ---"
  fi
}

if [[ -n "$SUITE_FILTER" ]]; then
  # Run specific suite
  matched=false
  for suite in "${SCRIPT_DIR}"/suites/*.sh; do
    if [[ "$(basename "$suite")" == "${SUITE_FILTER}"* ]]; then
      run_suite "$suite"
      matched=true
    fi
  done
  if ! $matched; then
    echo "ERROR: No suite matching '${SUITE_FILTER}'" >&2
    SUITES_FAILED=1
  fi
else
  # Run all suites in order
  for suite in "${SCRIPT_DIR}"/suites/*.sh; do
    [[ -f "$suite" ]] || continue
    run_suite "$suite"
  done
fi

# ── Tear down ─────────────────────────────────────────────────────────────────

if ! $NO_TEARDOWN; then
  echo ""
  echo "=== Tearing down containers ==="
  docker compose -f "$COMPOSE_FILE" down -v
fi

# ── Summary ───────────────────────────────────────────────────────────────────

print_test_summary "$TEST_RESULTS_FILE"

echo ""
echo "  Topology: ${TOPOLOGY}"
echo "  Suites run: ${SUITES_RUN}"
echo "  Suites failed: ${SUITES_FAILED}"
echo ""

if (( SUITES_FAILED > 0 )); then
  exit 1
fi
exit 0
