#!/usr/bin/env bash
# topology.sh — generators for RNS config files and docker-compose.yml
set -euo pipefail

# ── Config file generation ────────────────────────────────────────────────────

# gen_rns_config NODE_DIR TRANSPORT_ENABLED INTERFACES...
#   Writes NODE_DIR/config in ConfigObj format.
#   Interface spec: "type:key=val:key=val"
#     e.g. "TCPServerInterface:listen_ip=0.0.0.0:listen_port=4965"
#          "TCPClientInterface:target_host=node-a:target_port=4965"
gen_rns_config() {
  local node_dir="$1"
  local transport="$2"
  shift 2

  mkdir -p "$node_dir"

  local config_file="${node_dir}/config"
  {
    echo "[reticulum]"
    echo "enable_transport = ${transport}"
    echo "share_instance = No"
    echo ""
    echo "[interfaces]"
  } > "$config_file"

  local iface_num=0
  for spec in "$@"; do
    # Split spec on ':' using parameter substitution
    local iface_type="${spec%%:*}"
    local remainder="${spec#*:}"
    local iface_name="Interface ${iface_num}"
    (( iface_num++ )) || true

    {
      echo ""
      echo "  [[${iface_name}]]"
      echo "    type = ${iface_type}"
    } >> "$config_file"

    # Parse key=value pairs separated by ':'
    while [[ -n "$remainder" && "$remainder" != "$spec" ]]; do
      local pair
      if [[ "$remainder" == *:* ]]; then
        pair="${remainder%%:*}"
        remainder="${remainder#*:}"
      else
        pair="$remainder"
        remainder=""
      fi
      local key="${pair%%=*}"
      local val="${pair#*=}"
      echo "    ${key} = ${val}" >> "$config_file"
    done

    # Handle single-pair spec (type:key=val with no second ':')
    if [[ "$remainder" == "$spec" ]]; then
      : # no kv pairs after type (type-only spec)
    fi
  done
}

# ── Docker Compose generation ─────────────────────────────────────────────────

# gen_compose_header FILE
gen_compose_header() {
  local file="$1"
  cat > "$file" <<'EOF'
networks:
  rns-test:
    driver: bridge

services:
EOF
}

# gen_service FILE NAME HOST_PORT CONFIG_DIR [DEPENDS...]
#   Appends a service block.
gen_service() {
  local file="$1" name="$2" host_port="$3" config_dir="$4"
  shift 4
  local depends=("$@")

  cat >> "$file" <<EOF
  ${name}:
    image: rns-test
    container_name: ${name}
    volumes:
      - ${config_dir}:/etc/rns:ro
    ports:
      - "${host_port}:8080"
    networks:
      - rns-test
EOF

  if (( ${#depends[@]} > 0 )); then
    echo "    depends_on:" >> "$file"
    for dep in "${depends[@]}"; do
      cat >> "$file" <<EOF
      ${dep}:
        condition: service_healthy
EOF
    done
  fi

  echo "" >> "$file"
}

# gen_ports_env FILE MAPPING...
#   Writes NODE_X_PORT=808Y env file.
#   Mapping format: "NODE_NAME=PORT"
gen_ports_env() {
  local file="$1"
  shift
  > "$file"
  for mapping in "$@"; do
    echo "$mapping" >> "$file"
  done
}
