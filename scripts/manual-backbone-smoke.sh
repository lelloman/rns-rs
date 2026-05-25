#!/usr/bin/env bash
# Manual backbone smoke test for the VPS experiment.
#
# Starts two disposable local rns-server instances:
#   local-a -> VPS/backbone A
#   local-b -> VPS/backbone B
# Then verifies that fresh edge destinations can discover and communicate through
# the real backbone fabric.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_BIN="${ROOT_DIR}/target/release/rns-server"
if [[ ! -x "$DEFAULT_BIN" ]]; then
  DEFAULT_BIN="$(command -v rns-server || true)"
fi
DEFAULT_CTL="${ROOT_DIR}/target/release/rns-ctl"
if [[ ! -x "$DEFAULT_CTL" ]]; then
  DEFAULT_CTL="$(command -v rns-ctl || true)"
fi

BIN="${RNS_SERVER_BIN:-$DEFAULT_BIN}"
CTL_BIN="${RNS_CTL_BIN:-$DEFAULT_CTL}"
A_NAME="${RNS_SMOKE_A_NAME:-vps-eu}"
A_HOST="${RNS_SMOKE_A_HOST:-82.165.77.75}"
A_PORT="${RNS_SMOKE_A_PORT:-4242}"
A_TRANSPORT_ID="${RNS_SMOKE_A_TRANSPORT_ID:-}"
B_NAME="${RNS_SMOKE_B_NAME:-vps-us}"
B_HOST="${RNS_SMOKE_B_HOST:-74.208.55.138}"
B_PORT="${RNS_SMOKE_B_PORT:-4242}"
B_TRANSPORT_ID="${RNS_SMOKE_B_TRANSPORT_ID:-}"
TIMEOUT="${RNS_SMOKE_TIMEOUT:-120}"
CURL_TIMEOUT="${RNS_SMOKE_CURL_TIMEOUT:-5}"
WORKDIR=""
KEEP=false
HTTP_A=""
HTTP_B=""

usage() {
  cat <<'EOF'
Usage: scripts/manual-backbone-smoke.sh [OPTIONS]

Starts two temporary local rns-server nodes. Node A connects only to backbone A,
node B connects only to backbone B. The script then checks that they can discover,
packet, link, and channel each other through the live backbone fabric.

Defaults target the VPS experiment endpoints:
  A: vps-eu 82.165.77.75:4242
  B: vps-us 74.208.55.138:4242

Options:
  --bin PATH                 rns-server binary to run
  --ctl-bin PATH             rns-ctl binary to use for daemon status checks
  --a-name NAME              Label for backbone A
  --a-host HOST              Backbone A host/IP
  --a-port PORT              Backbone A port
  --a-transport-id HEX       Optional expected transport identity for A
  --b-name NAME              Label for backbone B
  --b-host HOST              Backbone B host/IP
  --b-port PORT              Backbone B port
  --b-transport-id HEX       Optional expected transport identity for B
  --timeout SECONDS          Per-step polling timeout (default: 120)
  --curl-timeout SECONDS     Per-request HTTP timeout (default: 5)
  --http-a PORT              Local HTTP port for node A (default: random)
  --http-b PORT              Local HTTP port for node B (default: random)
  --workdir DIR              Keep all temp state under DIR
  --keep                     Do not delete temp state on exit
  -h, --help                 Show this help

Environment overrides are also supported: RNS_SERVER_BIN, RNS_SMOKE_A_HOST,
RNS_SMOKE_A_PORT, RNS_SMOKE_B_HOST, RNS_SMOKE_B_PORT, RNS_SMOKE_TIMEOUT.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --ctl-bin) CTL_BIN="$2"; shift 2 ;;
    --a-name) A_NAME="$2"; shift 2 ;;
    --a-host) A_HOST="$2"; shift 2 ;;
    --a-port) A_PORT="$2"; shift 2 ;;
    --a-transport-id) A_TRANSPORT_ID="$2"; shift 2 ;;
    --b-name) B_NAME="$2"; shift 2 ;;
    --b-host) B_HOST="$2"; shift 2 ;;
    --b-port) B_PORT="$2"; shift 2 ;;
    --b-transport-id) B_TRANSPORT_ID="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --curl-timeout) CURL_TIMEOUT="$2"; shift 2 ;;
    --http-a) HTTP_A="$2"; shift 2 ;;
    --http-b) HTTP_B="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --keep) KEEP=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command '$1' not found" >&2
    exit 2
  fi
}

need_cmd curl
need_cmd jq
need_cmd python3
need_cmd base64

if [[ -z "$BIN" || ! -x "$BIN" ]]; then
  echo "ERROR: rns-server binary not found. Build it first or pass --bin PATH." >&2
  exit 2
fi
if [[ -z "$CTL_BIN" || ! -x "$CTL_BIN" ]]; then
  echo "ERROR: rns-ctl binary not found. Build it first or pass --ctl-bin PATH." >&2
  exit 2
fi

if [[ -z "$WORKDIR" ]]; then
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rns-backbone-smoke.XXXXXX")"
else
  mkdir -p "$WORKDIR"
  WORKDIR="$(cd "$WORKDIR" && pwd)"
fi

find_free_port() {
  python3 - <<'PYPORT'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PYPORT
}

HTTP_A="${HTTP_A:-$(find_free_port)}"
HTTP_B="${HTTP_B:-$(find_free_port)}"
SHARED_A="$(find_free_port)"
SHARED_B="$(find_free_port)"
CONTROL_A="$(find_free_port)"
CONTROL_B="$(find_free_port)"
if [[ "$HTTP_A" == "$HTTP_B" ]]; then
  HTTP_B="$(find_free_port)"
fi

PID_A=""
PID_B=""
cleanup() {
  local code=$?
  for pid in "$PID_A" "$PID_B"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  if ! $KEEP && [[ -n "${WORKDIR:-}" && -d "$WORKDIR" ]]; then
    rm -rf "$WORKDIR"
  else
    echo "Temp state kept at: $WORKDIR"
  fi
  exit "$code"
}
trap cleanup EXIT INT TERM

log() { printf '\n==> %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }

dump_debug_state() {
  local label="$1" port="$2" dir="$3"
  [[ -n "$port" ]] || return 0
  printf '\n--- %s packets ---\n' "$label" >&2
  api_get "$port" "/api/packets" 2>/dev/null | jq . >&2 || true
  printf '\n--- %s control-plane paths ---\n' "$label" >&2
  api_get "$port" "/api/paths" 2>/dev/null | jq . >&2 || true
  printf '\n--- %s daemon paths ---\n' "$label" >&2
  "$CTL_BIN" path --config "$dir" -t -j >&2 2>/dev/null || true
}

fail() {
  KEEP=true
  printf 'FAIL: %s\n' "$*" >&2
  dump_debug_state node-a "$HTTP_A" "$WORKDIR/node-a"
  dump_debug_state node-b "$HTTP_B" "$WORKDIR/node-b"
  printf '\n--- node-a log tail ---\n' >&2
  tail -n 80 "$WORKDIR/node-a/rns-server.log" >&2 2>/dev/null || true
  printf '\n--- node-b log tail ---\n' >&2
  tail -n 80 "$WORKDIR/node-b/rns-server.log" >&2 2>/dev/null || true
  exit 1
}

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

write_config() {
  local dir="$1" instance_name="$2" shared_port="$3" control_port="$4" label="$5" host="$6" port="$7" transport_id="$8"
  mkdir -p "$dir"
  cat >"$dir/config" <<EOF
[reticulum]
enable_transport = Yes
share_instance = Yes
instance_name = ${instance_name}
shared_instance_port = ${shared_port}
instance_control_port = ${control_port}
provider_bridge = yes
provider_socket_path = ${dir}/provider.sock
panic_on_interface_error = No
prefer_shorter_path = True
known_destinations_ttl = 172800
discover_interfaces = No

[interfaces]
  [[Backbone smoke via ${label}]]
    type = BackboneInterface
    enabled = yes
    remote = ${host}
    target_port = ${port}
    mode = full
EOF
  if [[ -n "$transport_id" ]]; then
    cat >>"$dir/config" <<EOF
    transport_identity = ${transport_id}
EOF
  fi
}

start_node() {
  local name="$1" dir="$2" http_port="$3"
  "$BIN" start \
    --config "$dir" \
    --http-host 127.0.0.1 \
    --http-port "$http_port" \
    --disable-auth \
    >"$dir/rns-server.log" 2>&1 &
  local pid=$!
  echo "$pid"
}

api_get() {
  local port="$1" path="$2"
  curl -fsS --connect-timeout 2 --max-time "$CURL_TIMEOUT" "http://127.0.0.1:${port}${path}"
}

api_post() {
  local port="$1" path="$2" body="$3"
  curl -fsS --connect-timeout 2 --max-time "$CURL_TIMEOUT" -H 'Content-Type: application/json' -d "$body" "http://127.0.0.1:${port}${path}"
}

poll_json() {
  local port="$1" path="$2" filter="$3" expected="$4" timeout="$5"
  local deadline=$((SECONDS + timeout))
  local value=""
  while (( SECONDS < deadline )); do
    value="$(api_get "$port" "$path" 2>/dev/null | jq -r "$filter" 2>/dev/null | head -n 1 || true)"
    if [[ "$value" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done
  printf 'last value for %s%s via jq [%s]: %s\n' "$port" "$path" "$filter" "${value:-<empty>}" >&2
  return 1
}

wait_health() {
  local port="$1" name="$2"
  poll_json "$port" "/health" '.status // empty' healthy 45 || fail "$name health did not become healthy"
  poll_json "$port" "/api/processes" '[.processes[] | select(.status == "running")] | length | tostring' 3 45 \
    || fail "$name did not start all supervised processes"
  poll_json "$port" "/api/processes" '[.processes[] | select(.ready == true)] | length | tostring' 3 90 \
    || fail "$name supervised processes did not become ready"
  pass "$name started on HTTP port $port"
}

wait_backbone_interface() {
  local dir="$1" name="$2" label="$3"
  local deadline=$((SECONDS + TIMEOUT))
  local stable=0
  local status=""
  while (( SECONDS < deadline )); do
    status="$("$CTL_BIN" --config "$dir" status -j 2>/dev/null || true)"
    if jq -e --arg name "Backbone smoke via ${name}" \
      '.interfaces[]? | select(.name == $name and .status == true)' \
      >/dev/null 2>&1 <<<"$status"; then
      stable=$((stable + 1))
      if (( stable >= 3 )); then
        pass "$label backbone interface is up"
        return 0
      fi
    else
      stable=0
    fi
    sleep 1
  done
  printf 'last status for %s:\n%s\n' "$label" "${status:-<empty>}" >&2
  fail "$label backbone interface did not stay up"
}

create_destination() {
  local port="$1" aspect="$2"
  local body
  body="$(jq -n --arg aspect "$aspect" '{type:"single", app_name:"manualsmoke", aspects:[$aspect], direction:"in", proof_strategy:"all"}')"
  api_post "$port" "/api/destination" "$body" | jq -r '.dest_hash'
}

create_outbound_destination() {
  local port="$1" aspect="$2" dest_hash="$3"
  local body
  body="$(jq -n --arg aspect "$aspect" --arg dest "$dest_hash" '{type:"single", app_name:"manualsmoke", aspects:[$aspect], direction:"out", dest_hash:$dest}')"
  api_post "$port" "/api/destination" "$body" | jq -r '.dest_hash'
}

announce_destination() {
  local port="$1" dest_hash="$2" marker="$3"
  local body
  body="$(jq -n --arg dh "$dest_hash" --arg ad "$(b64 "$marker")" '{dest_hash:$dh, app_data:$ad}')"
  api_post "$port" "/api/announce" "$body" >/dev/null
}

request_path() {
  local port="$1" dest_hash="$2"
  local body
  body="$(jq -n --arg dh "$dest_hash" '{dest_hash:$dh}')"
  api_post "$port" "/api/path/request" "$body" >/dev/null || true
}

wait_identity() {
  local port="$1" dest_hash="$2" label="$3"
  local deadline=$((SECONDS + TIMEOUT))
  local value=""
  while (( SECONDS < deadline )); do
    request_path "$port" "$dest_hash"
    value="$(api_get "$port" "/api/identity/${dest_hash}" 2>/dev/null | jq -r '.dest_hash // empty' 2>/dev/null || true)"
    if [[ "$value" == "$dest_hash" ]]; then
      pass "$label recalled identity $dest_hash"
      return 0
    fi
    sleep 3
  done
  fail "$label could not recall identity $dest_hash"
}

send_packet() {
  local port="$1" dest_hash="$2" payload="$3"
  local body
  body="$(jq -n --arg dh "$dest_hash" --arg data "$(b64 "$payload")" '{dest_hash:$dh, data:$data}')"
  api_post "$port" "/api/send" "$body" | jq -r '.packet_hash'
}

wait_packet() {
  local port="$1" packet_hash="$2" dest_hash="$3" label="$4"
  poll_json "$port" "/api/packets" ".packets[] | select(.packet_hash == \"${packet_hash}\" and .dest_hash == \"${dest_hash}\") | .packet_hash" "$packet_hash" "$TIMEOUT" \
    || fail "$label did not receive packet $packet_hash for $dest_hash"
  pass "$label received packet $packet_hash"
}

create_link() {
  local port="$1" dest_hash="$2"
  local body
  body="$(jq -n --arg dh "$dest_hash" '{dest_hash:$dh}')"
  api_post "$port" "/api/link" "$body" | jq -r '.link_id'
}

wait_link_active() {
  local port="$1" link_id="$2" label="$3"
  poll_json "$port" "/api/links" ".links[] | select(.link_id == \"${link_id}\") | .state" active "$TIMEOUT" \
    || fail "$label did not see link $link_id active"
  pass "$label saw link $link_id active"
}

send_channel() {
  local port="$1" link_id="$2" msgtype="$3" payload="$4"
  local body
  body="$(jq -n --arg lid "$link_id" --arg p "$(b64 "$payload")" --argjson mt "$msgtype" '{link_id:$lid, msgtype:$mt, payload:$p}')"
  api_post "$port" "/api/channel" "$body" >/dev/null
}

wait_channel() {
  local port="$1" link_id="$2" msgtype="$3" payload="$4" label="$5"
  local payload_b64
  payload_b64="$(b64 "$payload")"
  poll_json "$port" "/api/packets" ".packets[] | select(.dest_hash == \"channel:${link_id}:${msgtype}\") | .data_base64" "$payload_b64" "$TIMEOUT" \
    || fail "$label did not receive channel:${link_id}:${msgtype}"
  pass "$label received channel message on link $link_id"
}

log "Manual backbone smoke test"
echo "Binary: $BIN"
echo "Workdir: $WORKDIR"
echo "Node A: local HTTP ${HTTP_A}, shared ${SHARED_A}/${CONTROL_A}, backbone ${A_NAME} ${A_HOST}:${A_PORT}"
echo "Node B: local HTTP ${HTTP_B}, shared ${SHARED_B}/${CONTROL_B}, backbone ${B_NAME} ${B_HOST}:${B_PORT}"
echo "Timeout: ${TIMEOUT}s per step"

mkdir -p "$WORKDIR/node-a" "$WORKDIR/node-b"
write_config "$WORKDIR/node-a" "manual-smoke-a-$$" "$SHARED_A" "$CONTROL_A" "$A_NAME" "$A_HOST" "$A_PORT" "$A_TRANSPORT_ID"
write_config "$WORKDIR/node-b" "manual-smoke-b-$$" "$SHARED_B" "$CONTROL_B" "$B_NAME" "$B_HOST" "$B_PORT" "$B_TRANSPORT_ID"

log "Starting disposable local rns-server instances"
PID_A="$(start_node node-a "$WORKDIR/node-a" "$HTTP_A")"
PID_B="$(start_node node-b "$WORKDIR/node-b" "$HTTP_B")"
wait_health "$HTTP_A" node-a
wait_health "$HTTP_B" node-b
wait_backbone_interface "$WORKDIR/node-a" "$A_NAME" node-a
wait_backbone_interface "$WORKDIR/node-b" "$B_NAME" node-b

SMOKE_ID="$(date +%Y%m%d%H%M%S)-$$"
ASPECT_A="a"
ASPECT_B="b"

log "Creating and announcing fresh destinations"
DEST_A="$(create_destination "$HTTP_A" "$ASPECT_A")"
DEST_B="$(create_destination "$HTTP_B" "$ASPECT_B")"
echo "node-a destination: $DEST_A"
echo "node-b destination: $DEST_B"
announce_destination "$HTTP_A" "$DEST_A" "manual-smoke:${SMOKE_ID}:a"
announce_destination "$HTTP_B" "$DEST_B" "manual-smoke:${SMOKE_ID}:b"

log "Checking cross-backbone identity recall"
wait_identity "$HTTP_B" "$DEST_A" node-b
wait_identity "$HTTP_A" "$DEST_B" node-a

log "Checking cross-backbone packet delivery"
OUT_A_TO_B="$(create_outbound_destination "$HTTP_A" "$ASPECT_B" "$DEST_B")"
OUT_B_TO_A="$(create_outbound_destination "$HTTP_B" "$ASPECT_A" "$DEST_A")"
PACKET_A_TO_B="$(send_packet "$HTTP_A" "$OUT_A_TO_B" "manual smoke packet a-to-b ${SMOKE_ID}")"
PACKET_B_TO_A="$(send_packet "$HTTP_B" "$OUT_B_TO_A" "manual smoke packet b-to-a ${SMOKE_ID}")"
wait_packet "$HTTP_B" "$PACKET_A_TO_B" "$DEST_B" node-b
wait_packet "$HTTP_A" "$PACKET_B_TO_A" "$DEST_A" node-a

log "Checking link establishment and channel delivery through ${A_NAME} <-> ${B_NAME}"
LINK_B_TO_A="$(create_link "$HTTP_B" "$DEST_A")"
[[ -n "$LINK_B_TO_A" && "$LINK_B_TO_A" != "null" ]] || fail "node-b could not create link to node-a"
wait_link_active "$HTTP_B" "$LINK_B_TO_A" node-b
wait_link_active "$HTTP_A" "$LINK_B_TO_A" node-a
send_channel "$HTTP_B" "$LINK_B_TO_A" 71 "manual smoke channel b-to-a ${SMOKE_ID}"
wait_channel "$HTTP_A" "$LINK_B_TO_A" 71 "manual smoke channel b-to-a ${SMOKE_ID}" node-a
send_channel "$HTTP_A" "$LINK_B_TO_A" 72 "manual smoke channel a-to-b ${SMOKE_ID}"
wait_channel "$HTTP_B" "$LINK_B_TO_A" 72 "manual smoke channel a-to-b ${SMOKE_ID}" node-b

LINK_A_TO_B="$(create_link "$HTTP_A" "$DEST_B")"
[[ -n "$LINK_A_TO_B" && "$LINK_A_TO_B" != "null" ]] || fail "node-a could not create link to node-b"
wait_link_active "$HTTP_A" "$LINK_A_TO_B" node-a
wait_link_active "$HTTP_B" "$LINK_A_TO_B" node-b

log "Smoke test passed"
echo "node-a -> ${A_NAME}, node-b -> ${B_NAME}: announce, identity recall, packets, links and channel messages all worked."
