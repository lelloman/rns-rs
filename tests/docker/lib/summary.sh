#!/usr/bin/env bash
# summary.sh — print a comprehensive test results summary from the results file
#
# The results file is tab-delimited:
#   STATUS \t TOPOLOGY \t SUITE \t MESSAGE \t DETAIL

print_test_summary() {
  local results_file="${1:?Usage: print_test_summary RESULTS_FILE}"

  if [[ ! -f "$results_file" ]] || [[ ! -s "$results_file" ]]; then
    echo ""
    echo "  (no test results recorded)"
    return
  fi

  local total_pass=0 total_fail=0 total_skip=0
  local current_header=""
  local -a failures=()

  echo ""
  echo "============================================"
  echo "  TEST RESULTS SUMMARY"
  echo "============================================"

  while IFS=$'\t' read -r status topology suite msg detail; do
    # Group by suite + topology
    local header="${suite} [${topology}]"
    if [[ "$header" != "$current_header" ]]; then
      current_header="$header"
      echo ""
      echo "  ${header}"
    fi

    case "$status" in
      PASS)
        echo "    [PASS] ${msg}"
        (( total_pass++ )) || true
        ;;
      FAIL)
        if [[ -n "$detail" ]]; then
          echo "    [FAIL] ${msg} -- ${detail}"
        else
          echo "    [FAIL] ${msg}"
        fi
        (( total_fail++ )) || true
        if [[ -n "$detail" ]]; then
          failures+=("${suite} [${topology}]: ${msg} -- ${detail}")
        else
          failures+=("${suite} [${topology}]: ${msg}")
        fi
        ;;
      SKIP)
        echo "    [SKIP] ${msg}"
        (( total_skip++ )) || true
        ;;
    esac
  done < "$results_file"

  echo ""
  echo "--------------------------------------------"
  printf "  Total: %d passed, %d failed, %d skipped\n" "$total_pass" "$total_fail" "$total_skip"

  if (( total_fail > 0 )); then
    echo ""
    echo "  FAILURES:"
    for f in "${failures[@]}"; do
      echo "    - $f"
    done
  fi
  echo "============================================"
}
