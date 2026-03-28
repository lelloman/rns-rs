#!/usr/bin/env bash
# run-all.sh — Run the full Docker E2E test matrix across all topologies
#
# Usage:
#   ./tests/docker/run-all.sh              # Run everything
#   ./tests/docker/run-all.sh --no-scale   # Skip the star-30 scale test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SKIP_SCALE=false
NO_TEARDOWN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-scale)    SKIP_SCALE=true; shift ;;
    --no-teardown) NO_TEARDOWN=true; shift ;;
    *)
      echo "Usage: $0 [--no-scale] [--no-teardown]" >&2
      exit 1
      ;;
  esac
done

# ── Prerequisites ─────────────────────────────────────────────────────────────

for cmd in docker curl jq awk; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not found." >&2
    exit 1
  fi
done

if ! docker compose version &>/dev/null; then
  echo "ERROR: 'docker compose' (v2) is required." >&2
  exit 1
fi

# ── Build image once ──────────────────────────────────────────────────────────

echo "============================================"
echo "  Building rns-test Docker image"
echo "============================================"
docker build -t rns-test -f "${SCRIPT_DIR}/Dockerfile" "$REPO_ROOT"
echo ""

# ── Test matrix ───────────────────────────────────────────────────────────────
#
# Each entry: TOPOLOGY SUITE_FILTER DESCRIPTION
#
# chain-3:  01-07, 09 run; 08 runs (chain>=3); 10-12 skip
# chain-5:  03, 08 benefit from longer chain
# star-5:   07, 09, 11 are star-specific
# star-30:  10 is the scale test
# mesh-4:   12 is mesh-specific; 02, 04-06 also run on mesh

MATRIX=(
  "chain-3  all   Core tests on 3-node chain"
  "chain-5  03    Multi-hop announce on 5-node chain"
  "chain-5  08    Path table on 5-node chain"
  "star-5   all   Star topology tests"
  "mesh-4   all   Mesh topology tests"
  "chain-5  16    Multi-hop link on 5-node chain"
)

if ! $SKIP_SCALE; then
  MATRIX+=("star-30  10    Scale test (30 nodes)")
fi

export TEST_RESULTS_FILE
TEST_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/rns-test-results.XXXXXX")"
trap 'rm -f "$TEST_RESULTS_FILE"' EXIT

source "${SCRIPT_DIR}/lib/summary.sh"
source "${SCRIPT_DIR}/lib/readiness.sh"

TOTAL_RUNS=0
TOTAL_FAILED=0
RESULTS=()

teardown_flag=""
if $NO_TEARDOWN; then
  teardown_flag="--no-teardown"
fi

run_round() {
  local topology="$1" suite_filter="$2" description="$3"

  (( TOTAL_RUNS++ )) || true
  echo ""
  echo "============================================"
  echo "  [$TOTAL_RUNS] ${description}"
  echo "  topology=${topology}  suite=${suite_filter}"
  echo "============================================"
  echo ""

  local args=("--topology" "$topology")
  if [[ "$suite_filter" != "all" ]]; then
    args+=("--suite" "$suite_filter")
  fi
  if [[ -n "$teardown_flag" ]]; then
    args+=("$teardown_flag")
  fi

  # Generate topology
  local topo_type="${topology%%-*}"
  local topo_n="${topology#*-}"
  bash "${SCRIPT_DIR}/topologies/${topo_type}.sh" "$topo_n"

  local compose_file="${SCRIPT_DIR}/configs/${topology}/docker-compose.yml"
  local ports_file="${SCRIPT_DIR}/configs/${topology}/ports.env"

  # Start containers
  echo "Starting ${topology} containers..."
  if ! docker compose -f "$compose_file" up -d --wait; then
    echo "FAIL: Could not start containers for ${topology}"
    RESULTS+=("FAIL  ${description}")
    (( TOTAL_FAILED++ )) || true
    docker compose -f "$compose_file" down -v 2>/dev/null || true
    return
  fi

  # Clear stale port variables from previous rounds
  while IFS='=' read -r varname _; do
    unset "$varname"
  done < <(env | grep '_PORT=')

  # Export port variables and topology metadata
  set -a
  source "$ports_file"
  set +a
  export TOPO_TYPE="$topo_type" TOPO_N="$topo_n" TOPOLOGY="$topology"

  echo "Waiting for topology readiness..."
  if ! wait_for_topology_ready "$TOPO_TYPE" "$TOPO_N" 30; then
    echo "FAIL: Topology readiness check failed for ${topology}"
    RESULTS+=("FAIL  ${description}")
    (( TOTAL_FAILED++ )) || true
    docker compose -f "$compose_file" down -v 2>/dev/null || true
    return
  fi

  # Run suites
  local round_failed=false
  if [[ "$suite_filter" == "all" ]]; then
    for suite in "${SCRIPT_DIR}"/suites/*.sh; do
      [[ -f "$suite" ]] || continue
      local sname
      sname="$(basename "$suite" .sh)"
      echo ""
      echo "--- ${sname} ---"
      settle_topology_runtime 3
      if ! clear_topology_runtime_state; then
        round_failed=true
        echo "FAIL: Could not clear runtime state before ${sname}"
        continue
      fi
      local skip_chain3_suite03="0"
      if [[ "$topology" == "chain-3" && "$sname" == "03_announce_multihop" ]]; then
        skip_chain3_suite03="1"
      fi
      if ! RNS_E2E_SKIP_CHAIN3_REDUNDANT_SUITE03="$skip_chain3_suite03" bash "$suite"; then
        round_failed=true
        echo "--- Container logs (last 30 lines) ---"
        docker compose -f "$compose_file" logs --tail=30 2>/dev/null || true
        echo "--- End logs ---"
      fi
    done
  else
    for suite in "${SCRIPT_DIR}"/suites/*.sh; do
      if [[ "$(basename "$suite")" == "${suite_filter}"* ]]; then
        local sname
        sname="$(basename "$suite" .sh)"
        echo ""
        echo "--- ${sname} ---"
        settle_topology_runtime 3
        if ! clear_topology_runtime_state; then
          round_failed=true
          echo "FAIL: Could not clear runtime state before ${sname}"
          continue
        fi
        if ! bash "$suite"; then
          round_failed=true
          echo "--- Container logs (last 30 lines) ---"
          docker compose -f "$compose_file" logs --tail=30 2>/dev/null || true
          echo "--- End logs ---"
        fi
      fi
    done
  fi

  # Tear down
  if ! $NO_TEARDOWN; then
    docker compose -f "$compose_file" down -v 2>/dev/null || true
  fi

  if $round_failed; then
    RESULTS+=("FAIL  ${description}")
    (( TOTAL_FAILED++ )) || true
  else
    RESULTS+=("PASS  ${description}")
  fi
}

# ── Run the matrix ────────────────────────────────────────────────────────────

START_TIME=$SECONDS

for entry in "${MATRIX[@]}"; do
  # Split entry into fields
  read -r topology suite_filter description <<< "$entry"
  # description may have lost its spaces from read; re-extract it
  description="${entry#*  *  }"
  run_round "$topology" "$suite_filter" "$description"
done

# ── Standalone tests ──────────────────────────────────────────────────────────
# Tests with custom topologies that don't fit the matrix pattern.

run_standalone() {
  local test_dir="$1" description="$2"

  (( TOTAL_RUNS++ )) || true
  echo ""
  echo "============================================"
  echo "  [$TOTAL_RUNS] ${description}"
  echo "============================================"
  echo ""

  local run_args=()
  if $NO_TEARDOWN; then
    run_args+=("--no-teardown")
  fi

  if SKIP_BUILD=true bash "${test_dir}/run.sh" "${run_args[@]+"${run_args[@]}"}"; then
    RESULTS+=("PASS  ${description}")
  else
    RESULTS+=("FAIL  ${description}")
    (( TOTAL_FAILED++ )) || true
  fi
}

run_standalone "${SCRIPT_DIR}/shared-client-reconnect" \
  "Shared client reconnection (issue #3)"

run_standalone "${SCRIPT_DIR}/rns-server" \
  "rns-server process supervision"

ELAPSED=$(( SECONDS - START_TIME ))

# ── Summary ───────────────────────────────────────────────────────────────────

print_test_summary "$TEST_RESULTS_FILE"

echo ""
echo "============================================"
echo "  FULL TEST MATRIX RESULTS"
echo "============================================"
for r in "${RESULTS[@]}"; do
  echo "  $r"
done
echo "--------------------------------------------"
echo "  Runs: ${TOTAL_RUNS}  Failed: ${TOTAL_FAILED}  Time: ${ELAPSED}s"
echo "============================================"

if (( TOTAL_FAILED > 0 )); then
  exit 1
fi
exit 0
