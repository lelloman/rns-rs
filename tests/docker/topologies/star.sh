#!/usr/bin/env bash
# star.sh N — generate a star topology: hub + (N-1) spokes
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${SCRIPT_DIR}/lib/topology.sh"

N="${1:?Usage: star.sh N}"
TOPO_NAME="star-${N}"
OUT_DIR="${SCRIPT_DIR}/configs/${TOPO_NAME}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

gen_compose_header "${OUT_DIR}/docker-compose.yml"

port_mappings=()

# Hub node: transport-enabled TCP server
hub_config="${OUT_DIR}/hub"
gen_rns_config "$hub_config" "True" \
  "TCPServerInterface:listen_ip=0.0.0.0:listen_port=4965"

gen_service "${OUT_DIR}/docker-compose.yml" "hub" "8081" "$hub_config"
port_mappings+=("HUB_PORT=8081")

# Spoke nodes: connect to hub
for (( i=1; i<N; i++ )); do
  spoke_name="spoke-$(printf '%02d' "$i")"
  host_port=$(( 8081 + i ))
  spoke_config="${OUT_DIR}/${spoke_name}"

  gen_rns_config "$spoke_config" "False" \
    "TCPClientInterface:target_host=hub:target_port=4965"

  gen_service "${OUT_DIR}/docker-compose.yml" "$spoke_name" "$host_port" \
    "$spoke_config" "hub"

  varname="SPOKE_$(printf '%02d' "$i")_PORT"
  port_mappings+=("${varname}=${host_port}")
done

gen_ports_env "${OUT_DIR}/ports.env" "${port_mappings[@]}"

echo "Generated ${TOPO_NAME}: 1 hub + $((N - 1)) spokes, ports 8081-$(( 8080 + N ))"
echo "  Compose: ${OUT_DIR}/docker-compose.yml"
echo "  Ports:   ${OUT_DIR}/ports.env"
