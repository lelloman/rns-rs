#!/usr/bin/env bash
# chain.sh N — generate a chain of N nodes: node-a — node-b — ... — node-{N}
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/topology.sh"

N="${1:?Usage: chain.sh N}"
TOPO_NAME="chain-${N}"
OUT_DIR="${SCRIPT_DIR}/configs/${TOPO_NAME}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Node names: a, b, c, ...
node_name() {
  local idx="$1"
  printf "\\$(printf '%03o' "$(( idx + 97 ))")"
}

# Generate compose file
gen_compose_header "${OUT_DIR}/docker-compose.yml"

port_mappings=()

for (( i=0; i<N; i++ )); do
  local_name="node-$(node_name $i)"
  host_port=$(( 8081 + i ))
  config_dir="${OUT_DIR}/${local_name}"

  # Build interface specs
  ifaces=("TCPServerInterface:listen_ip=0.0.0.0:listen_port=4965")

  # Connect to previous node (TCP client)
  if (( i > 0 )); then
    prev_name="node-$(node_name $((i - 1)))"
    ifaces+=("TCPClientInterface:target_host=${prev_name}:target_port=4965")
  fi

  # All chain nodes are transport-enabled
  gen_rns_config "$config_dir" "True" "${ifaces[@]}"

  # Add service to compose
  depends=()
  if (( i > 0 )); then
    depends+=("node-$(node_name $((i - 1)))")
  fi
  gen_service "${OUT_DIR}/docker-compose.yml" "$local_name" "$host_port" \
    "${config_dir}" "${depends[@]}"

  # Track port mapping
  varname="NODE_$(node_name $i | tr '[:lower:]' '[:upper:]')_PORT"
  port_mappings+=("${varname}=${host_port}")
done

gen_ports_env "${OUT_DIR}/ports.env" "${port_mappings[@]}"

echo "Generated ${TOPO_NAME}: ${N} nodes, ports 8081-$(( 8080 + N ))"
echo "  Compose: ${OUT_DIR}/docker-compose.yml"
echo "  Ports:   ${OUT_DIR}/ports.env"
