#!/usr/bin/env bash
# mesh.sh N — generate a fully-connected mesh of N nodes
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/topology.sh"

N="${1:?Usage: mesh.sh N}"
TOPO_NAME="mesh-${N}"
OUT_DIR="${SCRIPT_DIR}/configs/${TOPO_NAME}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

node_name() {
  local idx="$1"
  printf "\\$(printf '%03o' "$(( idx + 97 ))")"
}

gen_compose_header "${OUT_DIR}/docker-compose.yml"

port_mappings=()

for (( i=0; i<N; i++ )); do
  local_name="node-$(node_name $i)"
  host_port=$(( 8081 + i ))
  config_dir="${OUT_DIR}/${local_name}"

  # Every node runs a TCP server
  ifaces=("TCPServerInterface:listen_ip=0.0.0.0:listen_port=4965")

  # Connect as TCP client to all nodes with lower index
  for (( j=0; j<i; j++ )); do
    peer="node-$(node_name $j)"
    ifaces+=("TCPClientInterface:target_host=${peer}:target_port=4965")
  done

  # All mesh nodes are transport-enabled
  gen_rns_config "$config_dir" "True" "${ifaces[@]}"

  # depends_on: all nodes with lower index
  depends=()
  for (( j=0; j<i; j++ )); do
    depends+=("node-$(node_name $j)")
  done

  gen_service "${OUT_DIR}/docker-compose.yml" "$local_name" "$host_port" \
    "$config_dir" "${depends[@]}"

  varname="NODE_$(node_name $i | tr '[:lower:]' '[:upper:]')_PORT"
  port_mappings+=("${varname}=${host_port}")
done

gen_ports_env "${OUT_DIR}/ports.env" "${port_mappings[@]}"

echo "Generated ${TOPO_NAME}: ${N} fully-connected nodes, ports 8081-$(( 8080 + N ))"
echo "  Compose: ${OUT_DIR}/docker-compose.yml"
echo "  Ports:   ${OUT_DIR}/ports.env"
