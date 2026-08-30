#!/usr/bin/env bash
# Privileged Linux-to-Linux rntun E2E coverage.
set -euo pipefail

GATEWAY=rntun-gateway
CLIENT=rntun-client
TARGET=rntun-target
GATEWAY_CONFIG=/etc/rntun/config.toml
SPLIT_CONFIG=/etc/rntun/split.toml
FULL_CONFIG=/etc/rntun/full.toml

passed=0
failed=0

pass() {
  echo "  PASS: $1"
  passed=$((passed + 1))
}

fail() {
  echo "  FAIL: $1" >&2
  failed=$((failed + 1))
}

assert_command() {
  local description=$1
  shift
  if "$@"; then pass "$description"; else fail "$description"; fi
}

wait_for() {
  local timeout=$1 description=$2
  shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "TIMEOUT: ${description}" >&2
  return 1
}

status_field_is() {
  local container=$1 config=$2 expression=$3 expected=$4
  local actual
  actual=$(docker exec "$container" rntun status --config "$config" --json 2>/dev/null \
    | jq -r "$expression" 2>/dev/null) || return 1
  [[ "$actual" == "$expected" ]]
}

start_gateway() {
  docker exec -d -e RUST_LOG=rns_tun=info "$GATEWAY" sh -c \
    "exec rntun listen --config '$GATEWAY_CONFIG' >>/tmp/rntun-gateway.log 2>&1"
}

stop_gateway() {
  docker exec "$GATEWAY" pkill -TERM -x rntun 2>/dev/null || true
  wait_for 10 "gateway process to stop" docker exec "$GATEWAY" sh -c '! pgrep -x rntun'
}

start_client() {
  local config=$1 log=$2
  docker exec -d -e RUST_LOG=rns_tun=info "$CLIENT" sh -c \
    "exec rntun connect '$DESTINATION' --config '$config' >>'$log' 2>&1"
}

stop_client() {
  docker exec "$CLIENT" pkill -TERM -x rntun 2>/dev/null || true
  wait_for 10 "client process to stop" docker exec "$CLIENT" sh -c '! pgrep -x rntun'
}

client_active() {
  local config=$1 full=$2
  status_field_is "$CLIENT" "$config" '.lifecycle' active \
    && status_field_is "$CLIENT" "$config" '.sessions | length' 1 \
    && status_field_is "$CLIENT" "$config" '.full_tunnel_verified' "$full"
}

gateway_active_session() {
  status_field_is "$GATEWAY" "$GATEWAY_CONFIG" '.sessions | length' 1 \
    && status_field_is "$GATEWAY" "$GATEWAY_CONFIG" '.sessions[0].state' active
}

target_log_contains() {
  docker logs "$TARGET" 2>&1 | grep -q "$1"
}

no_tunnel_policy() {
  ! docker exec "$CLIENT" ip rule show | grep -q 'lookup 21076' \
    && ! docker exec "$CLIENT" ip -6 rule show | grep -q '^110:.*prohibit' \
    && ! docker exec "$CLIENT" ip link show rntun-full >/dev/null 2>&1
}

echo "=== Preparing identities and gateway policy ==="
CLIENT_HASH=$(docker exec "$CLIENT" rntun identity --config "$FULL_CONFIG")
docker exec "$GATEWAY" sh -c 'cat > /data/gateway-policy.toml <<EOF
[gateway]
address = "10.77.0.1/24"

[clients.'"$CLIENT_HASH"']
enabled = true
address = "10.77.0.2"
allow_routes = ["0.0.0.0/0"]
allow_internet = true
allow_peers = []
idle_timeout_seconds = 120
EOF'
docker exec "$GATEWAY" sh -c \
  'iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -d 198.18.0.0/24 -j MASQUERADE'
start_gateway
wait_for 30 "gateway status socket" status_field_is \
  "$GATEWAY" "$GATEWAY_CONFIG" '.lifecycle' active
DESTINATION=$(docker exec "$GATEWAY" rntun status --config "$GATEWAY_CONFIG" --json \
  | jq -r '.destination_hash')
if [[ "$DESTINATION" =~ ^[0-9a-f]{32}$ ]]; then pass "gateway destination available"; else fail "gateway destination available"; exit 1; fi

echo ""
echo "=== Split-tunnel routing and orderly restoration ==="
docker exec "$CLIENT" sh -c 'rm -rf /run/rntun-resolved && mkdir -p /run/rntun-resolved'
start_client "$SPLIT_CONFIG" /tmp/rntun-split.log
assert_command "split client and gateway become active" wait_for 60 "split session" client_active "$SPLIT_CONFIG" false
assert_command "gateway reports the split session active" wait_for 10 "gateway split session" gateway_active_session
assert_command "split route selects the TUN policy table" docker exec "$CLIENT" sh -c \
  "ip route get 198.18.0.10 | grep -q 'dev rntun-split.*table 21076'"
assert_command "split-tunnel packet reaches remote subnet" docker exec "$CLIENT" ping -c 3 -W 3 198.18.0.10
docker exec "$CLIENT" sh -c "printf split-dns-e2e | timeout 1 socat - UDP4:198.18.0.53:53 >/dev/null || true"
assert_command "hard-coded DNS-address traffic crosses split tunnel" wait_for 5 "split DNS receipt" \
  target_log_contains split-dns-e2e
assert_command "unselected underlay route remains physical" docker exec "$CLIENT" sh -c \
  "ip route get 172.31.76.3 | grep -q 'dev eth0'"
assert_command "split tunnel does not alter resolver state" docker exec "$CLIENT" sh -c \
  'test ! -s /run/rntun-resolved/commands.log'
stop_client
assert_command "orderly split teardown removes route and TUN" wait_for 10 "split cleanup" docker exec "$CLIENT" sh -c \
  "! ip rule show | grep -q 'to 198.18.0.0/24 lookup 21076' && ! ip link show rntun-split >/dev/null 2>&1 && test ! -e /data/client-split/linux-ownership.json"

echo ""
echo "=== Full tunnel, DNS selection, IPv6 blocking, and NAT ==="
docker exec "$CLIENT" sh -c 'rm -rf /run/rntun-resolved && mkdir -p /run/rntun-resolved'
start_client "$FULL_CONFIG" /tmp/rntun-full.log
assert_command "full-tunnel client becomes verified and active" wait_for 60 "full session" client_active "$FULL_CONFIG" true
assert_command "gateway reports the full-tunnel session active" wait_for 10 "gateway full session" gateway_active_session
assert_command "unmarked IPv4 uses fail-closed tunnel table" docker exec "$CLIENT" sh -c \
  "ip rule show | grep -q 'not from all fwmark 0x5254 lookup 21076' && ip route show table 21076 | grep -q 'blackhole default'"
assert_command "marked Reticulum underlay retains physical table" docker exec "$CLIENT" sh -c \
  "ip rule show | grep -q 'fwmark 0x5254 lookup main'"
assert_command "full-tunnel Internet packet crosses gateway NAT" docker exec "$CLIENT" ping -c 5 -W 3 198.18.0.10
docker exec "$CLIENT" sh -c "printf full-dns-e2e | timeout 1 socat - UDP4:198.18.0.53:53 >/dev/null || true"
assert_command "hard-coded approved DNS traffic crosses full tunnel" wait_for 5 "full DNS receipt" \
  target_log_contains full-dns-e2e
assert_command "resolver backend installs approved DNS and catch-all domain" docker exec "$CLIENT" sh -c \
  "grep -q 'DNS Servers: 198.18.0.53' /run/rntun-resolved/rntun-full && grep -q 'DNS Domain: ~.' /run/rntun-resolved/rntun-full"
assert_command "unmarked IPv6 cannot bypass the IPv4 tunnel" docker exec "$CLIENT" sh -c \
  "ip -6 rule show | grep -q '^110:.*prohibit' && ! ping -6 -c 1 -W 1 fd76:1::3"

echo ""
echo "=== Link loss keeps fail-closed state and reconnects ==="
stop_gateway
assert_command "client enters reconnecting state" wait_for 30 "client reconnecting" status_field_is \
  "$CLIENT" "$FULL_CONFIG" '.reconnecting' true
assert_command "IPv4, DNS, and IPv6 protections remain during reconnect" docker exec "$CLIENT" sh -c \
  "ip route show table 21076 | grep -q 'blackhole default' && test -f /run/rntun-resolved/rntun-full && ip -6 rule show | grep -q '^110:.*prohibit'"
assert_command "ordinary traffic fails closed while gateway is absent" docker exec "$CLIENT" sh -c \
  '! ping -c 1 -W 1 198.18.0.10'
start_gateway
assert_command "session automatically reconnects" wait_for 75 "full session reconnect" client_active "$FULL_CONFIG" true
assert_command "traffic resumes after reconnect" docker exec "$CLIENT" ping -c 3 -W 3 198.18.0.10

echo ""
echo "=== Abrupt client death and stale-state reconciliation ==="
docker exec "$CLIENT" pkill -KILL -x rntun
assert_command "crash leaves durable ownership journal" wait_for 10 "stale journal" docker exec "$CLIENT" test -f /data/client-full/linux-ownership.json
assert_command "crash leaves fail-closed policy for explicit cleanup" docker exec "$CLIENT" sh -c \
  "ip rule show | grep -q 'lookup 21076' && ip -6 rule show | grep -q '^110:.*prohibit'"
assert_command "cleanup reconciles stale network and DNS state" docker exec "$CLIENT" rntun cleanup --config "$FULL_CONFIG"
assert_command "cleanup removes only rntun-owned state" wait_for 10 "stale state removal" no_tunnel_policy
assert_command "cleanup reverts resolver state and journal" docker exec "$CLIENT" sh -c \
  'test ! -e /run/rntun-resolved/rntun-full && test ! -e /data/client-full/linux-ownership.json'

echo ""
echo "=== Failed DNS setup rolls back all partial mutations ==="
docker exec "$CLIENT" sh -c ': > /tmp/rntun-setup-failure.log'
docker exec -d -e RNTUN_TEST_RESOLVECTL_FAIL=domain "$CLIENT" sh -c \
  "exec rntun connect '$DESTINATION' --config '$FULL_CONFIG' >>/tmp/rntun-setup-failure.log 2>&1"
assert_command "injected resolver failure terminates setup" wait_for 60 "setup failure" docker exec "$CLIENT" sh -c \
  "grep -q 'injected resolvectl domain failure' /tmp/rntun-setup-failure.log && ! pgrep -x rntun"
assert_command "failed setup restores routes, DNS, and journal" wait_for 10 "setup rollback" docker exec "$CLIENT" sh -c \
  "! ip rule show | grep -q 'lookup 21076' && ! ip -6 rule show | grep -q '^110:.*prohibit' && test ! -e /run/rntun-resolved/rntun-full && test ! -e /data/client-full/linux-ownership.json"

stop_gateway

echo ""
echo "============================================"
echo "rntun E2E results: ${passed} passed, ${failed} failed"
echo "============================================"
(( failed == 0 ))
