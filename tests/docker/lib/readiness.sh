#!/usr/bin/env bash
# readiness.sh — topology readiness checks for Docker E2E tests
set -euo pipefail

wait_for_up_interfaces() {
  local port="$1" expected="$2" timeout="${3:-30}"
  local deadline=$((SECONDS + timeout))
  local count=""

  while (( SECONDS < deadline )); do
    count=$(curl -sf "http://localhost:${port}/api/interfaces" 2>/dev/null \
      | jq -r '[.interfaces[] | select(.status == "up")] | length' 2>/dev/null) || true
    if [[ -n "$count" && "$count" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done

  echo "TIMEOUT: interface readiness on port ${port}, expected ${expected} up interfaces, last got ${count:-<empty>}" >&2
  return 1
}

wait_for_topology_ready() {
  local topo_type="${1:-${TOPO_TYPE:-}}"
  local topo_n="${2:-${TOPO_N:-}}"
  local timeout="${3:-30}"

  case "$topo_type" in
    chain)
      local last_idx=$(( topo_n - 1 ))
      for (( i=0; i<=last_idx; i++ )); do
        local node_letter
        node_letter=$(printf "\\$(printf '%03o' "$(( i + 97 ))")")
        local varname="NODE_$(echo "$node_letter" | tr '[:lower:]' '[:upper:]')_PORT"
        local port="${!varname}"
        local expected="1"
        if (( i > 0 && i < last_idx )); then
          expected="2"
        fi
        if ! wait_for_up_interfaces "$port" "$expected" "$timeout"; then
          return 1
        fi
      done
      ;;
    star)
      if ! wait_for_up_interfaces "${HUB_PORT:?Need HUB_PORT}" "$(( topo_n - 1 ))" "$timeout"; then
        return 1
      fi
      for (( i=1; i<topo_n; i++ )); do
        local varname="SPOKE_$(printf '%02d' "$i")_PORT"
        local port="${!varname}"
        if ! wait_for_up_interfaces "$port" "1" "$timeout"; then
          return 1
        fi
      done
      ;;
    mesh)
      local expected="$(( topo_n - 1 ))"
      for (( i=0; i<topo_n; i++ )); do
        local node_letter
        node_letter=$(printf "\\$(printf '%03o' "$(( i + 97 ))")")
        local varname="NODE_$(echo "$node_letter" | tr '[:lower:]' '[:upper:]')_PORT"
        local port="${!varname}"
        if ! wait_for_up_interfaces "$port" "$expected" "$timeout"; then
          return 1
        fi
      done
      ;;
  esac

  return 0
}

clear_node_runtime_state() {
  local port="$1"

  curl -sf -X POST "http://localhost:${port}/api/announce_queues/clear" >/dev/null 2>&1 || return 1

  for path in announces packets proofs link_events resource_events; do
    curl -sf "http://localhost:${port}/api/${path}?clear=true" >/dev/null 2>&1 || true
  done

  return 0
}

clear_topology_runtime_state() {
  for var in $(env | grep '_PORT=' | sort); do
    local port="${var#*=}"
    clear_node_runtime_state "$port" || return 1
  done

  return 0
}

settle_topology_runtime() {
  local seconds="${1:-3}"
  sleep "$seconds"
}
