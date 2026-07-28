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
DAILY=false
for argument in "$@"; do
  if [[ "$argument" == --daily ]]; then
    DAILY=true
    break
  fi
done

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
CURL_TIMEOUT="${RNS_SMOKE_CURL_TIMEOUT:-5}"
if $DAILY; then
  TIMEOUT="${RNS_SMOKE_TIMEOUT:-300}"
  RESOURCE_SIZES="${RNS_SMOKE_RESOURCE_SIZES:-1024,100000,1048575,1048576}"
  RESOURCE_CONCURRENCY="${RNS_SMOKE_RESOURCE_CONCURRENCY:-2}"
  LINK_ITERATIONS="${RNS_SMOKE_LINK_ITERATIONS:-2}"
  LINK_CONCURRENCY="${RNS_SMOKE_LINK_CONCURRENCY:-3}"
  LATENCY_MS="${RNS_SMOKE_LATENCY_MS:-150}"
  JITTER_MS="${RNS_SMOKE_JITTER_MS:-75}"
  RATE_KBPS="${RNS_SMOKE_RATE_KBPS:-2000}"
  RECONNECT_CYCLES="${RNS_SMOKE_RECONNECT_CYCLES:-1}"
else
  TIMEOUT="${RNS_SMOKE_TIMEOUT:-120}"
  RESOURCE_SIZES="${RNS_SMOKE_RESOURCE_SIZES:-}"
  RESOURCE_CONCURRENCY="${RNS_SMOKE_RESOURCE_CONCURRENCY:-1}"
  LINK_ITERATIONS="${RNS_SMOKE_LINK_ITERATIONS:-1}"
  LINK_CONCURRENCY="${RNS_SMOKE_LINK_CONCURRENCY:-1}"
  LATENCY_MS="${RNS_SMOKE_LATENCY_MS:-0}"
  JITTER_MS="${RNS_SMOKE_JITTER_MS:-0}"
  RATE_KBPS="${RNS_SMOKE_RATE_KBPS:-0}"
  RECONNECT_CYCLES="${RNS_SMOKE_RECONNECT_CYCLES:-0}"
fi
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
  --daily                    Daily-check profile with resources, concurrency,
                             impairment and forced reconnect coverage
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
  --resource-sizes CSV       Resource sizes in bytes to verify in both directions
  --resource-concurrency N   Simultaneous Resources per direction and size (default: 1)
  --link-iterations COUNT    Batches of link pairs to establish (default: 1)
  --link-concurrency N       Simultaneous links per direction and batch (default: 1)
  --latency-ms MS            Added one-way delay on each local-to-VPS leg (default: 0)
  --jitter-ms MS             Added random one-way delay on each leg (default: 0)
  --rate-kbps KBPS           Approximate per-direction rate limit on each leg (default: 0)
  --reconnect-cycles N       Forced Backbone disconnect/recovery cycles (default: 0)
  --http-a PORT              Local HTTP port for node A (default: random)
  --http-b PORT              Local HTTP port for node B (default: random)
  --workdir DIR              Keep all temp state under DIR
  --keep                     Do not delete temp state on exit
  -h, --help                 Show this help

Environment overrides are also supported: RNS_SERVER_BIN, RNS_SMOKE_A_HOST,
RNS_SMOKE_A_PORT, RNS_SMOKE_B_HOST, RNS_SMOKE_B_PORT, RNS_SMOKE_TIMEOUT,
RNS_SMOKE_RESOURCE_SIZES, RNS_SMOKE_RESOURCE_CONCURRENCY,
RNS_SMOKE_LINK_ITERATIONS, RNS_SMOKE_LINK_CONCURRENCY, RNS_SMOKE_LATENCY_MS,
RNS_SMOKE_JITTER_MS, RNS_SMOKE_RATE_KBPS and RNS_SMOKE_RECONNECT_CYCLES.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --daily) DAILY=true; shift ;;
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
    --resource-sizes) RESOURCE_SIZES="$2"; shift 2 ;;
    --resource-concurrency) RESOURCE_CONCURRENCY="$2"; shift 2 ;;
    --link-iterations) LINK_ITERATIONS="$2"; shift 2 ;;
    --link-concurrency) LINK_CONCURRENCY="$2"; shift 2 ;;
    --latency-ms) LATENCY_MS="$2"; shift 2 ;;
    --jitter-ms) JITTER_MS="$2"; shift 2 ;;
    --rate-kbps) RATE_KBPS="$2"; shift 2 ;;
    --reconnect-cycles) RECONNECT_CYCLES="$2"; shift 2 ;;
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
need_cmd sha256sum

for value_name in LATENCY_MS JITTER_MS RATE_KBPS; do
  value="${!value_name}"
  if [[ ! "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    option_name="${value_name,,}"
    echo "ERROR: --${option_name//_/-} must be a non-negative number" >&2
    exit 2
  fi
done

for value_name in LINK_ITERATIONS LINK_CONCURRENCY RESOURCE_CONCURRENCY; do
  value="${!value_name}"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    option_name="${value_name,,}"
    echo "ERROR: --${option_name//_/-} must be a positive integer" >&2
    exit 2
  fi
done
if [[ ! "$RECONNECT_CYCLES" =~ ^[0-9]+$ ]]; then
  echo "ERROR: --reconnect-cycles must be a non-negative integer" >&2
  exit 2
fi
if [[ -n "$RESOURCE_SIZES" ]]; then
  IFS=',' read -r -a RESOURCE_SIZE_LIST <<<"$RESOURCE_SIZES"
  for size in "${RESOURCE_SIZE_LIST[@]}"; do
    if [[ ! "$size" =~ ^[1-9][0-9]*$ ]]; then
      echo "ERROR: --resource-sizes must be comma-separated positive integers" >&2
      exit 2
    fi
  done
else
  RESOURCE_SIZE_LIST=()
fi

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
PROXY_PID_A=""
PROXY_PID_B=""
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  for pid in "$PID_A" "$PID_B" "$PROXY_PID_A" "$PROXY_PID_B"; do
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
  printf '\n--- %s resource events ---\n' "$label" >&2
  api_get "$port" "/api/resource_events" 2>/dev/null \
    | jq '.resource_events |= map(.data_base64_length = (.data_base64 // "" | length) | del(.data_base64))' >&2 \
    || true
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
  for proxy_log in "$WORKDIR"/*-fault-proxy.log; do
    [[ -e "$proxy_log" ]] || continue
    printf '\n--- %s ---\n' "$(basename "$proxy_log")" >&2
    tail -n 80 "$proxy_log" >&2 || true
  done
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

start_fault_proxy() {
  local name="$1" listen_port="$2" upstream_host="$3" upstream_port="$4"
  python3 "$ROOT_DIR/scripts/backbone-fault-proxy.py" \
    --listen-port "$listen_port" \
    --upstream-host "$upstream_host" \
    --upstream-port "$upstream_port" \
    --latency-ms "$LATENCY_MS" \
    --jitter-ms "$JITTER_MS" \
    --rate-kbps "$RATE_KBPS" \
    >"$WORKDIR/${name}-fault-proxy.log" 2>&1 &
  echo "$!"
}

wait_fault_proxy() {
  local pid="$1" log_file="$2" label="$3" deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    kill -0 "$pid" 2>/dev/null || fail "$label fault proxy exited during startup"
    if [[ -s "$log_file" ]]; then
      pass "$label fault proxy started as PID $pid"
      return 0
    fi
    sleep 1
  done
  fail "$label fault proxy did not become ready"
}

proxy_connection_count() {
  local log_file="$1"
  grep -c '^session [0-9][0-9]* connected$' "$log_file" 2>/dev/null || true
}

wait_proxy_reconnected() {
  local pid="$1" log_file="$2" previous_count="$3" label="$4"
  local deadline=$((SECONDS + TIMEOUT)) count
  while (( SECONDS < deadline )); do
    kill -0 "$pid" 2>/dev/null || fail "$label fault proxy exited during reconnect"
    count="$(proxy_connection_count "$log_file")"
    if (( count > previous_count )); then
      pass "$label opened a new Backbone session"
      return 0
    fi
    sleep 1
  done
  fail "$label did not reconnect its Backbone session"
}

api_get() {
  local port="$1" path="$2"
  curl -fsS --connect-timeout 2 --max-time "$CURL_TIMEOUT" "http://127.0.0.1:${port}${path}"
}

api_post() {
  local port="$1" path="$2" body="$3"
  curl -fsS --connect-timeout 2 --max-time "$CURL_TIMEOUT" -H 'Content-Type: application/json' -d "$body" "http://127.0.0.1:${port}${path}"
}

api_post_file() {
  local port="$1" path="$2" body_file="$3"
  curl -fsS --connect-timeout 2 --max-time "$CURL_TIMEOUT" \
    -H 'Content-Type: application/json' --data-binary "@${body_file}" \
    "http://127.0.0.1:${port}${path}"
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
  local deadline=$((SECONDS + TIMEOUT)) state="" close_reason=""
  while (( SECONDS < deadline )); do
    state="$(api_get "$port" "/api/links" 2>/dev/null \
      | jq -r --arg lid "$link_id" '.links[] | select(.link_id == $lid) | .state' 2>/dev/null \
      | head -n 1 || true)"
    if [[ "$state" == active ]]; then
      pass "$label saw link $link_id active"
      return 0
    fi
    close_reason="$(api_get "$port" "/api/link_events" 2>/dev/null \
      | jq -r --arg lid "$link_id" '[.link_events[] | select(.link_id == $lid and .event_type == "closed")] | last | .reason // empty' 2>/dev/null \
      || true)"
    if [[ "$state" == closed || -n "$close_reason" ]]; then
      fail "$label saw link $link_id close before becoming active: ${close_reason:-unknown}"
    fi
    sleep 1
  done
  fail "$label did not see link $link_id active (last state: ${state:-missing})"
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

clear_resource_events() {
  local port="$1"
  api_get "$port" "/api/resource_events?clear=true" >/dev/null 2>&1 || true
}

write_resource_payload() {
  local path="$1" size="$2" seed="${3:-0}"
  python3 - "$path" "$size" "$seed" <<'PY'
import sys

path = sys.argv[1]
remaining = int(sys.argv[2])
seed = int(sys.argv[3])
pattern = bytes((value + seed) % 256 for value in range(256))
with open(path, "wb") as output:
    while remaining:
        chunk = pattern[:min(remaining, len(pattern))]
        output.write(chunk)
        remaining -= len(chunk)
PY
}

wait_resource_count() {
  local port="$1" link_id="$2" event_type="$3" count="$4" label="$5"
  poll_json "$port" "/api/resource_events" \
    "([.resource_events[] | select(.link_id == \"${link_id}\" and .event_type == \"${event_type}\")] | length) >= ${count} | tostring" \
    true "$TIMEOUT" || fail "$label expected at least $count resource '$event_type' events on link $link_id"
}

verify_received_resource() {
  local port="$1" link_id="$2" payload_file="$3" metadata="$4" label="$5"
  local expected_sha received_sha metadata_b64
  expected_sha="$(sha256sum "$payload_file" | awk '{print $1}')"
  metadata_b64="$(b64 "$metadata")"
  received_sha="$(api_get "$port" "/api/resource_events" \
    | jq -r --arg lid "$link_id" --arg metadata "$metadata_b64" \
      '[.resource_events[] | select(.link_id == $lid and .event_type == "received" and .metadata_base64 == $metadata)] | last | .data_base64 // empty' \
    | base64 -d \
    | sha256sum \
    | awk '{print $1}')"
  [[ "$received_sha" == "$expected_sha" ]] \
    || fail "$label resource checksum mismatch: expected $expected_sha, got $received_sha"
}

send_resource_file() {
  local port="$1" link_id="$2" payload_file="$3" body_file="$4" metadata="$5"
  local encoded_file="${body_file}.b64"
  base64 <"$payload_file" | tr -d '\n' >"$encoded_file"
  jq -n --arg lid "$link_id" --rawfile data "$encoded_file" --arg metadata "$(b64 "$metadata")" \
    '{link_id:$lid, data:$data, metadata:$metadata}' >"$body_file"
  api_post_file "$port" "/api/resource" "$body_file" >/dev/null
}

wait_resource_transfer() {
  local sender_port="$1" receiver_port="$2" link_id="$3" payload_file="$4" label="$5"
  local expected_sha received_sha
  expected_sha="$(sha256sum "$payload_file" | awk '{print $1}')"

  poll_json "$receiver_port" "/api/resource_events" \
    "[.resource_events[] | select(.link_id == \"${link_id}\" and .event_type == \"received\")] | length | tostring" \
    1 "$TIMEOUT" || fail "$label did not receive resource on link $link_id"
  poll_json "$sender_port" "/api/resource_events" \
    "[.resource_events[] | select(.link_id == \"${link_id}\" and .event_type == \"completed\")] | length | tostring" \
    1 "$TIMEOUT" || fail "$label sender did not complete resource on link $link_id"

  received_sha="$(api_get "$receiver_port" "/api/resource_events" \
    | jq -r --arg lid "$link_id" '[.resource_events[] | select(.link_id == $lid and .event_type == "received")] | last | .data_base64' \
    | base64 -d \
    | sha256sum \
    | awk '{print $1}')"
  [[ "$received_sha" == "$expected_sha" ]] \
    || fail "$label resource checksum mismatch: expected $expected_sha, got $received_sha"
  pass "$label resource checksum $received_sha"
}

exercise_resource() {
  local sender_port="$1" receiver_port="$2" link_id="$3" size="$4" direction="$5"
  local payload_file="$WORKDIR/resource-${direction}-${size}.bin"
  local body_file="$WORKDIR/resource-${direction}-${size}.json"
  local started elapsed
  write_resource_payload "$payload_file" "$size"
  clear_resource_events "$sender_port"
  clear_resource_events "$receiver_port"
  started="$(date +%s%3N)"
  send_resource_file "$sender_port" "$link_id" "$payload_file" "$body_file" \
    "manual-smoke:${SMOKE_ID}:${direction}:${size}"
  wait_resource_transfer "$sender_port" "$receiver_port" "$link_id" "$payload_file" \
    "$direction ${size}-byte"
  elapsed=$(( $(date +%s%3N) - started ))
  pass "$direction ${size}-byte resource completed in ${elapsed}ms"
}

exercise_concurrent_resources() {
  local link_id="$1" size="$2" count="$3"
  local started elapsed index direction sender_port receiver_port payload_file body_file metadata pid
  local -a pids=()

  clear_resource_events "$HTTP_A"
  clear_resource_events "$HTTP_B"
  started="$(date +%s%3N)"
  for (( index = 1; index <= count; index++ )); do
    for direction in a-to-b b-to-a; do
      if [[ "$direction" == "a-to-b" ]]; then
        sender_port="$HTTP_A"
      else
        sender_port="$HTTP_B"
      fi
      payload_file="$WORKDIR/resource-${direction}-${size}-${index}.bin"
      body_file="$WORKDIR/resource-${direction}-${size}-${index}.json"
      metadata="manual-smoke:${SMOKE_ID}:${direction}:${size}:${index}"
      seed="$index"
      [[ "$direction" == "b-to-a" ]] && seed=$((seed + 127))
      write_resource_payload "$payload_file" "$size" "$seed"
      send_resource_file "$sender_port" "$link_id" "$payload_file" "$body_file" "$metadata" &
      pids+=("$!")
    done
  done
  for pid in "${pids[@]}"; do
    wait "$pid" || fail "concurrent Resource API request failed"
  done

  wait_resource_count "$HTTP_A" "$link_id" received "$count" node-a
  wait_resource_count "$HTTP_A" "$link_id" completed "$((count * 2))" node-a
  wait_resource_count "$HTTP_B" "$link_id" received "$count" node-b
  wait_resource_count "$HTTP_B" "$link_id" completed "$((count * 2))" node-b

  for (( index = 1; index <= count; index++ )); do
    for direction in a-to-b b-to-a; do
      if [[ "$direction" == "a-to-b" ]]; then
        receiver_port="$HTTP_B"
      else
        receiver_port="$HTTP_A"
      fi
      payload_file="$WORKDIR/resource-${direction}-${size}-${index}.bin"
      metadata="manual-smoke:${SMOKE_ID}:${direction}:${size}:${index}"
      verify_received_resource "$receiver_port" "$link_id" "$payload_file" "$metadata" \
        "$direction concurrent transfer $index/$count"
    done
  done
  elapsed=$(( $(date +%s%3N) - started ))
  pass "$((count * 2)) concurrent ${size}-byte resources completed in ${elapsed}ms"
}

create_link_batch() {
  local initiator_port="$1" listener_port="$2" dest_hash="$3" direction="$4" batch="$5" count="$6"
  local index response_file pid link_id
  local -a pids=() response_files=()
  for (( index = 1; index <= count; index++ )); do
    response_file="$WORKDIR/link-${direction}-${batch}-${index}.json"
    api_post "$initiator_port" "/api/link" "$(jq -n --arg dh "$dest_hash" '{dest_hash:$dh}')" >"$response_file" &
    pids+=("$!")
    response_files+=("$response_file")
  done
  for pid in "${pids[@]}"; do
    wait "$pid" || fail "$direction batch $batch link creation request failed"
  done
  for (( index = 0; index < count; index++ )); do
    link_id="$(jq -r '.link_id // empty' "${response_files[$index]}")"
    [[ -n "$link_id" ]] || fail "$direction batch $batch link $((index + 1)) returned no link ID"
    wait_link_active "$initiator_port" "$link_id" "$direction initiator batch $batch link $((index + 1))"
    wait_link_active "$listener_port" "$link_id" "$direction listener batch $batch link $((index + 1))"
  done
}

exercise_reconnect_cycle() {
  local cycle="$1" before_a before_b link_id size packet_a_to_b packet_b_to_a
  before_a="$(proxy_connection_count "$WORKDIR/node-a-fault-proxy.log")"
  before_b="$(proxy_connection_count "$WORKDIR/node-b-fault-proxy.log")"
  kill -USR1 "$PROXY_PID_A"
  kill -USR1 "$PROXY_PID_B"
  wait_proxy_reconnected "$PROXY_PID_A" "$WORKDIR/node-a-fault-proxy.log" "$before_a" node-a
  wait_proxy_reconnected "$PROXY_PID_B" "$WORKDIR/node-b-fault-proxy.log" "$before_b" node-b
  wait_backbone_interface "$WORKDIR/node-a" "$A_NAME" node-a
  wait_backbone_interface "$WORKDIR/node-b" "$B_NAME" node-b

  announce_destination "$HTTP_A" "$DEST_A" "manual-smoke:${SMOKE_ID}:reconnect:${cycle}:a"
  announce_destination "$HTTP_B" "$DEST_B" "manual-smoke:${SMOKE_ID}:reconnect:${cycle}:b"

  # A reconnected TCP session is only the link-layer prerequisite. Confirm that
  # the replacement announces have restored routable paths before attributing a
  # subsequent link-handshake failure to retained link state.
  sleep 10
  packet_a_to_b="$(send_packet "$HTTP_A" "$OUT_A_TO_B" \
    "reconnect cycle ${cycle} packet a-to-b ${SMOKE_ID}")"
  packet_b_to_a="$(send_packet "$HTTP_B" "$OUT_B_TO_A" \
    "reconnect cycle ${cycle} packet b-to-a ${SMOKE_ID}")"
  wait_packet "$HTTP_B" "$packet_a_to_b" "$DEST_B" "node-b reconnect cycle $cycle"
  wait_packet "$HTTP_A" "$packet_b_to_a" "$DEST_A" "node-a reconnect cycle $cycle"

  link_id="$(create_link "$HTTP_B" "$DEST_A")"
  [[ -n "$link_id" && "$link_id" != "null" ]] || fail "reconnect cycle $cycle could not create link"
  wait_link_active "$HTTP_B" "$link_id" "node-b reconnect cycle $cycle"
  wait_link_active "$HTTP_A" "$link_id" "node-a reconnect cycle $cycle"
  send_channel "$HTTP_B" "$link_id" 81 "reconnect cycle ${cycle} b-to-a ${SMOKE_ID}"
  wait_channel "$HTTP_A" "$link_id" 81 "reconnect cycle ${cycle} b-to-a ${SMOKE_ID}" node-a
  send_channel "$HTTP_A" "$link_id" 82 "reconnect cycle ${cycle} a-to-b ${SMOKE_ID}"
  wait_channel "$HTTP_B" "$link_id" 82 "reconnect cycle ${cycle} a-to-b ${SMOKE_ID}" node-b
  if (( ${#RESOURCE_SIZE_LIST[@]} > 0 )); then
    size="${RESOURCE_SIZE_LIST[0]}"
    exercise_resource "$HTTP_B" "$HTTP_A" "$link_id" "$size" "reconnect-${cycle}-b-to-a"
    exercise_resource "$HTTP_A" "$HTTP_B" "$link_id" "$size" "reconnect-${cycle}-a-to-b"
  fi
  pass "forced Backbone reconnect cycle $cycle recovered end-to-end"
}

PROFILE_NAME="custom/default"
$DAILY && PROFILE_NAME="daily"
log "Manual backbone smoke test"
echo "Profile: $PROFILE_NAME"
echo "Binary: $BIN"
echo "Workdir: $WORKDIR"
echo "Node A: local HTTP ${HTTP_A}, shared ${SHARED_A}/${CONTROL_A}, backbone ${A_NAME} ${A_HOST}:${A_PORT}"
echo "Node B: local HTTP ${HTTP_B}, shared ${SHARED_B}/${CONTROL_B}, backbone ${B_NAME} ${B_HOST}:${B_PORT}"
echo "Timeout: ${TIMEOUT}s per step"
echo "Link iterations: ${LINK_ITERATIONS}"
echo "Link concurrency: ${LINK_CONCURRENCY}"
echo "Resource sizes: ${RESOURCE_SIZES:-disabled}"
echo "Resource concurrency: ${RESOURCE_CONCURRENCY}"
echo "Network impairment per VPS leg: latency ${LATENCY_MS}ms, jitter ${JITTER_MS}ms, rate ${RATE_KBPS}kbps"
echo "Forced reconnect cycles: ${RECONNECT_CYCLES}"

mkdir -p "$WORKDIR/node-a" "$WORKDIR/node-b"
CONFIG_A_HOST="$A_HOST"
CONFIG_A_PORT="$A_PORT"
CONFIG_B_HOST="$B_HOST"
CONFIG_B_PORT="$B_PORT"
if [[ "$LATENCY_MS" != 0 || "$JITTER_MS" != 0 || "$RATE_KBPS" != 0 || "$RECONNECT_CYCLES" != 0 ]]; then
  PROXY_PORT_A="$(find_free_port)"
  PROXY_PORT_B="$(find_free_port)"
  log "Starting disposable network impairment proxies"
  PROXY_PID_A="$(start_fault_proxy node-a "$PROXY_PORT_A" "$A_HOST" "$A_PORT")"
  PROXY_PID_B="$(start_fault_proxy node-b "$PROXY_PORT_B" "$B_HOST" "$B_PORT")"
  wait_fault_proxy "$PROXY_PID_A" "$WORKDIR/node-a-fault-proxy.log" node-a
  wait_fault_proxy "$PROXY_PID_B" "$WORKDIR/node-b-fault-proxy.log" node-b
  CONFIG_A_HOST="127.0.0.1"
  CONFIG_A_PORT="$PROXY_PORT_A"
  CONFIG_B_HOST="127.0.0.1"
  CONFIG_B_PORT="$PROXY_PORT_B"
fi
write_config "$WORKDIR/node-a" "manual-smoke-a-$$" "$SHARED_A" "$CONTROL_A" "$A_NAME" "$CONFIG_A_HOST" "$CONFIG_A_PORT" "$A_TRANSPORT_ID"
write_config "$WORKDIR/node-b" "manual-smoke-b-$$" "$SHARED_B" "$CONTROL_B" "$B_NAME" "$CONFIG_B_HOST" "$CONFIG_B_PORT" "$B_TRANSPORT_ID"

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

if (( ${#RESOURCE_SIZE_LIST[@]} > 0 )); then
  log "Checking resource transfers through ${A_NAME} <-> ${B_NAME}"
  for size in "${RESOURCE_SIZE_LIST[@]}"; do
    if (( RESOURCE_CONCURRENCY == 1 )); then
      exercise_resource "$HTTP_B" "$HTTP_A" "$LINK_B_TO_A" "$size" "b-to-a"
      exercise_resource "$HTTP_A" "$HTTP_B" "$LINK_B_TO_A" "$size" "a-to-b"
    else
      exercise_concurrent_resources "$LINK_B_TO_A" "$size" "$RESOURCE_CONCURRENCY"
    fi
  done
fi

LINK_A_TO_B="$(create_link "$HTTP_A" "$DEST_B")"
[[ -n "$LINK_A_TO_B" && "$LINK_A_TO_B" != "null" ]] || fail "node-a could not create link to node-b"
wait_link_active "$HTTP_A" "$LINK_A_TO_B" node-a
wait_link_active "$HTTP_B" "$LINK_A_TO_B" node-b

if (( LINK_ITERATIONS > 1 || LINK_CONCURRENCY > 1 )); then
  log "Checking repeated/concurrent bidirectional link establishment"
  if (( LINK_CONCURRENCY > 1 )); then
    create_link_batch "$HTTP_B" "$HTTP_A" "$DEST_A" b-to-a 1 "$((LINK_CONCURRENCY - 1))"
    create_link_batch "$HTTP_A" "$HTTP_B" "$DEST_B" a-to-b 1 "$((LINK_CONCURRENCY - 1))"
  fi
  for (( iteration = 2; iteration <= LINK_ITERATIONS; iteration++ )); do
    create_link_batch "$HTTP_B" "$HTTP_A" "$DEST_A" b-to-a "$iteration" "$LINK_CONCURRENCY"
    create_link_batch "$HTTP_A" "$HTTP_B" "$DEST_B" a-to-b "$iteration" "$LINK_CONCURRENCY"
  done
fi

if (( RECONNECT_CYCLES > 0 )); then
  log "Checking recovery from forced Backbone disconnects"
  for (( cycle = 1; cycle <= RECONNECT_CYCLES; cycle++ )); do
    exercise_reconnect_cycle "$cycle"
  done
fi

log "Smoke test passed"
echo "node-a -> ${A_NAME}, node-b -> ${B_NAME}: announce, identity recall, packets, links and channel messages all worked."
if (( ${#RESOURCE_SIZE_LIST[@]} > 0 )); then
  echo "Bidirectional Resource sizes verified: ${RESOURCE_SIZES} bytes."
fi
if (( LINK_ITERATIONS > 1 || LINK_CONCURRENCY > 1 )); then
  echo "Bidirectional link stress verified: ${LINK_ITERATIONS} batches at concurrency ${LINK_CONCURRENCY}."
fi
if (( RECONNECT_CYCLES > 0 )); then
  echo "Forced Backbone disconnect/recovery cycles verified: ${RECONNECT_CYCLES}."
fi
