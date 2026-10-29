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
docker build --build-arg CARGO_BUILD_JOBS --build-arg CARGO_PROFILE_RELEASE_CODEGEN_UNITS -t rns-test -f "${SCRIPT_DIR}/Dockerfile" "$REPO_ROOT"
echo ""

# ── Test matrix ───────────────────────────────────────────────────────────────
#
# Each entry: TOPOLOGY SUITE_FILTER DESCRIPTION
#
# chain-3:  01-07, 09, 13-15, 18-19, 21 run; 08 runs (chain>=3); 10-12, 17 skip
# chain-5:  03, 08 and 16 benefit from a longer chain, in one round
# star-5:   07, 09, 11 and 17 are star-specific
# star-30:  10 is the scale test
# mesh-4:   12 is mesh-specific; 02, 04-06 also run on mesh

# Suite filters are "all" or a comma-separated list of suite number prefixes.
# One chain-5 round carries every suite that needs five nodes: starting and
# tearing down a topology costs far more than the suites themselves.
MATRIX=(
  "chain-3  all       Core tests on 3-node chain"
  "chain-5  03,08,16  Multi-hop announce, path table and multi-hop link on 5-node chain"
  "star-5   all       Star topology tests"
  "mesh-4   all       Mesh topology tests"
)

if ! $SKIP_SCALE; then
  MATRIX+=("star-30  10    Scale test (30 nodes)")
fi

export TEST_RESULTS_FILE
TEST_RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/rns-test-results.XXXXXX")"
trap 'rm -f "$TEST_RESULTS_FILE"' EXIT

source "${SCRIPT_DIR}/lib/summary.sh"
source "${SCRIPT_DIR}/lib/readiness.sh"

# Containers are disposable: give them two seconds to exit on SIGTERM instead
# of compose's ten-second default, which dominated teardown time.
export COMPOSE_STOP_TIMEOUT="${COMPOSE_STOP_TIMEOUT:-2}"

TOTAL_RUNS=0
TOTAL_FAILED=0
RESULTS=()

teardown_flag=""
if $NO_TEARDOWN; then
  teardown_flag="--no-teardown"
fi

# suite_matches_filter SUITE_NAME FILTER
#   FILTER is "all" or a comma-separated list of suite prefixes ("03,08").
suite_matches_filter() {
  local name="$1" filter="$2"
  if [[ "$filter" == "all" ]]; then
    return 0
  fi
  local prefix
  local IFS=,
  for prefix in $filter; do
    if [[ "$name" == "${prefix}"* ]]; then
      return 0
    fi
  done
  return 1
}

run_round() {
  local topology="$1" suite_filter="$2" description="$3"

  (( TOTAL_RUNS++ )) || true
  local round_start=$SECONDS
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
    docker compose -f "$compose_file" down -v -t "$COMPOSE_STOP_TIMEOUT" 2>/dev/null || true
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
    docker compose -f "$compose_file" down -v -t "$COMPOSE_STOP_TIMEOUT" 2>/dev/null || true
    return
  fi

  # Run suites
  local round_failed=false
  local needs_settle=false
  for suite in "${SCRIPT_DIR}"/suites/*.sh; do
    [[ -f "$suite" ]] || continue
    local sname
    sname="$(basename "$suite" .sh)"
    suite_matches_filter "$sname" "$suite_filter" || continue
    echo ""
    echo "--- ${sname} ---"
    # Let the previous suite's traffic die down, but only when one ran: a
    # suite that skipped itself leaves nothing to settle.
    if $needs_settle; then
      settle_topology_runtime 3
    fi
    if ! clear_topology_runtime_state; then
      round_failed=true
      echo "FAIL: Could not clear runtime state before ${sname}"
      continue
    fi
    local skip_chain3_suite03="0"
    if [[ "$topology" == "chain-3" && "$suite_filter" == "all" && "$sname" == "03_announce_multihop" ]]; then
      skip_chain3_suite03="1"
    fi
    local ran_before
    ran_before=$(count_ran_results)
    if ! RNS_E2E_SKIP_CHAIN3_REDUNDANT_SUITE03="$skip_chain3_suite03" bash "$suite"; then
      round_failed=true
      echo "--- Container logs (last 30 lines) ---"
      docker compose -f "$compose_file" logs --tail=30 2>/dev/null || true
      echo "--- End logs ---"
    fi
    if (( $(count_ran_results) > ran_before )); then
      needs_settle=true
    else
      needs_settle=false
    fi
  done

  # Tear down
  if ! $NO_TEARDOWN; then
    docker compose -f "$compose_file" down -v -t "$COMPOSE_STOP_TIMEOUT" 2>/dev/null || true
  fi

  local round_elapsed=$(( SECONDS - round_start ))
  if $round_failed; then
    RESULTS+=("FAIL  ${description} (${round_elapsed}s)")
    (( TOTAL_FAILED++ )) || true
  else
    RESULTS+=("PASS  ${description} (${round_elapsed}s)")
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
  local round_start=$SECONDS
  echo ""
  echo "============================================"
  echo "  [$TOTAL_RUNS] ${description}"
  echo "============================================"
  echo ""

  local run_args=()
  if $NO_TEARDOWN; then
    run_args+=("--no-teardown")
  fi

  local status=0
  SKIP_BUILD=true bash "${test_dir}/run.sh" "${run_args[@]+"${run_args[@]}"}" || status=$?
  local round_elapsed=$(( SECONDS - round_start ))
  if (( status == 0 )); then
    RESULTS+=("PASS  ${description} (${round_elapsed}s)")
  else
    RESULTS+=("FAIL  ${description} (${round_elapsed}s)")
    (( TOTAL_FAILED++ )) || true
  fi
}

run_standalone "${SCRIPT_DIR}/shared-client-reconnect" \
  "Shared client reconnection (issue #3)"

run_standalone "${SCRIPT_DIR}/shared-instance-links" \
  "Shared instance sibling and adjacent-peer links (issue #183)"

run_standalone "${SCRIPT_DIR}/rns-server" \
  "rns-server process supervision"

run_standalone "${SCRIPT_DIR}/nat-punch" \
  "Direct Link NAT hole punching (accept_all default)"

run_standalone "${SCRIPT_DIR}/rntun" \
  "rntun Linux split/full tunnel, DNS, reconnect, and cleanup"

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
