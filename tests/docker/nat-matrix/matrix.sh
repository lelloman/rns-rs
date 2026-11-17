#!/usr/bin/env bash
# matrix.sh — Direct Link NAT matrix, run inside one privileged container.
#
# Each case builds a small internet out of network namespaces: a bridge
# (172.29.0.0/24) with the facilitator on it, and NAT routers whose LANs
# (172.29.1.0/24, 172.29.2.0/24) hold the two peers. iptables in each
# router's namespace gives it one of these NAT behaviours:
#
#   full-cone        endpoint-independent mapping and filtering
#   restricted       endpoint-independent mapping, address-dependent filtering
#   port-restricted  endpoint-independent mapping, address and port-dependent
#                    filtering
#   symmetric        endpoint-dependent mapping (a random port per
#                    destination), address and port-dependent filtering
#
# No router forwards traffic from its LAN back to its own public address
# (no hairpinning). Peer A's NAT varies, peer B sits behind a
# port-restricted NAT; a symmetric NAT also meets a full-cone and a
# restricted one; in the same-LAN case both peers sit behind one
# port-restricted NAT; and the IPv6 case adds NAT66 (fd29::/64 and LANs
# fd29:1::/64, fd29:2::/64) and probes the facilitator over IPv6. Each
# case asserts whether the link upgrades to a
# direct path, over which candidate, or correctly stays on the transport
# path, and that the link carries messages either way.
#
# Usage: matrix.sh [case ...]   (default: every case)
set -uo pipefail

FAC_IP=172.29.0.30
FAC_IP6=fd29::30
PROBE_ADDR="$FAC_IP:4343"
WORK=/tmp/nat-matrix
PIDS=()
NAMESPACES=()
PASSES=0
FAILURES=0

pass() { echo "  PASS: $1"; PASSES=$((PASSES + 1)); }
fail() { echo "  FAIL: $1${2:+ — $2}"; FAILURES=$((FAILURES + 1)); }

in_ns() {
  local ns="$1"
  shift
  ip netns exec "$ns" "$@"
}

api_get() { in_ns "$1" curl -sf "http://127.0.0.1:8080$2"; }
api_post() {
  in_ns "$1" curl -sf -X POST -H "Content-Type: application/json" \
    -d "$3" "http://127.0.0.1:8080$2"
}

# poll NS PATH JQ EXPECTED TIMEOUT
poll() {
  local ns="$1" path="$2" filter="$3" expected="$4" timeout="$5"
  local deadline=$((SECONDS + timeout)) got=""
  while ((SECONDS < deadline)); do
    got=$(api_get "$ns" "$path" 2>/dev/null | jq -r "$filter" 2>/dev/null) || true
    [[ "$got" == "$expected" ]] && return 0
    sleep 1
  done
  echo "    (timeout: $ns $path | $filter = '$got', wanted '$expected')" >&2
  return 1
}

teardown() {
  local pid
  for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
    wait "$pid" 2>/dev/null || true
  done
  PIDS=()
  local ns
  # Remove the veth pairs first: a deleted namespace's links go away only
  # once the kernel gets round to it, and the next case reuses the names.
  for ns in "${NAMESPACES[@]+"${NAMESPACES[@]}"}"; do
    in_ns "$ns" ip link del eth0 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
  done
  NAMESPACES=()
  ip link del br-inet 2>/dev/null || true
}
trap teardown EXIT

new_ns() {
  ip netns add "$1"
  NAMESPACES+=("$1")
  in_ns "$1" ip link set lo up
}

# on_internet NS IP — a namespace with eth0 on the internet bridge.
on_internet() {
  local ns="$1" addr="$2"
  new_ns "$ns"
  ip link add "i-$ns" type veth peer name "e-$ns"
  ip link set "i-$ns" master br-inet up
  ip link set "e-$ns" netns "$ns"
  in_ns "$ns" ip link set "e-$ns" name eth0
  in_ns "$ns" ip addr add "$addr/24" dev eth0
  in_ns "$ns" ip link set eth0 up
}

# router NS WAN_IP LAN_PREFIX — a NAT router: eth0 on the internet, br-lan
# at LAN_PREFIX.1/24.
router() {
  local ns="$1" wan="$2" lan="$3"
  on_internet "$ns" "$wan"
  in_ns "$ns" sysctl -qw net.ipv4.ip_forward=1
  in_ns "$ns" ip link add br-lan type bridge
  in_ns "$ns" ip addr add "$lan.1/24" dev br-lan
  in_ns "$ns" ip link set br-lan up
}

# lan_host NS ROUTER IP LAN_PREFIX — a host on ROUTER's LAN.
lan_host() {
  local ns="$1" router_ns="$2" addr="$3" lan="$4"
  new_ns "$ns"
  ip link add "l-$ns" type veth peer name "e-$ns"
  ip link set "l-$ns" netns "$router_ns"
  in_ns "$router_ns" ip link set "l-$ns" master br-lan up
  ip link set "e-$ns" netns "$ns"
  in_ns "$ns" ip link set "e-$ns" name eth0
  in_ns "$ns" ip addr add "$addr/24" dev eth0
  in_ns "$ns" ip link set eth0 up
  in_ns "$ns" ip route add default via "$lan.1"
}

# nat ROUTER TYPE HOST_IP — give ROUTER the NAT behaviour TYPE toward the
# internet for the host HOST_IP.
#
# The cone types forward every inbound UDP datagram to the host's port of
# the same number (their mappings keep the port) and filter in FORWARD. A
# plain masquerading router would instead take an unsolicited datagram to
# its public port as a connection of its own, and then give the host's
# next datagram to that peer another port: forwarding first keeps the
# mapping endpoint-independent, as RFC 4787 asks of these NATs.
nat() {
  local r="$1" type="$2" host="$3"
  case "$type" in
    full-cone | restricted | port-restricted)
      in_ns "$r" iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
      in_ns "$r" iptables -t nat -A PREROUTING -i eth0 -p udp -j DNAT --to-destination "$host"
      in_ns "$r" iptables -A FORWARD -i eth0 -o br-lan -m conntrack \
        --ctstate ESTABLISHED,RELATED -j ACCEPT
      ;;
  esac
  case "$type" in
    full-cone)
      ;;
    restricted)
      # Inbound only from addresses the host has sent to.
      in_ns "$r" iptables -I FORWARD 1 -i br-lan -o eth0 -m recent --name contacted --rdest --set
      in_ns "$r" iptables -A FORWARD -i eth0 -o br-lan -m recent --name contacted \
        --rsource --rcheck --seconds 120 -j ACCEPT
      in_ns "$r" iptables -A FORWARD -i eth0 -o br-lan -j DROP
      ;;
    port-restricted)
      # Inbound only from address and port pairs the host has sent to:
      # the replies of its own conntrack entries.
      in_ns "$r" iptables -A FORWARD -i eth0 -o br-lan -j DROP
      ;;
    symmetric)
      # A random public port for each new destination.
      in_ns "$r" iptables -t nat -A POSTROUTING -o eth0 -p udp -j MASQUERADE --random-fully
      in_ns "$r" iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
      ;;
    *)
      echo "unknown NAT type $type" >&2
      return 1
      ;;
  esac
}

# ipv6_nat66 — add IPv6 to the two-NAT layout: the internet on fd29::/64,
# A's LAN on fd29:1::/64 and B's on fd29:2::/64, each router doing
# port-restricted NAT66 like its IPv4 NAT. The facilitator answers on
# both families; the peers probe it over IPv6.
ipv6_nat66() {
  local ns
  for ns in fac ra rb ha hb; do
    in_ns "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0
  done
  in_ns fac ip -6 addr add "$FAC_IP6/64" dev eth0 nodad
  in_ns ra ip -6 addr add fd29::10/64 dev eth0 nodad
  in_ns rb ip -6 addr add fd29::20/64 dev eth0 nodad
  in_ns ra ip -6 addr add fd29:1::1/64 dev br-lan nodad
  in_ns rb ip -6 addr add fd29:2::1/64 dev br-lan nodad
  in_ns ha ip -6 addr add fd29:1::2/64 dev eth0 nodad
  in_ns hb ip -6 addr add fd29:2::2/64 dev eth0 nodad
  in_ns ha ip -6 route add default via fd29:1::1
  in_ns hb ip -6 route add default via fd29:2::1
  local r host
  for r in ra rb; do
    host=fd29:1::2
    [[ "$r" == rb ]] && host=fd29:2::2
    in_ns "$r" sysctl -qw net.ipv6.conf.all.forwarding=1
    in_ns "$r" ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE || return 1
    in_ns "$r" ip6tables -t nat -A PREROUTING -i eth0 -p udp -j DNAT --to-destination "$host"
    in_ns "$r" ip6tables -A FORWARD -i eth0 -o br-lan -m conntrack \
      --ctstate ESTABLISHED,RELATED -j ACCEPT
    in_ns "$r" ip6tables -A FORWARD -i eth0 -o br-lan -j DROP
  done
}

# start_node NS ROLE — run rns-ctl in NS; ROLE is facilitator or peer.
start_node() {
  local ns="$1" role="$2" dir="$WORK/$1"
  mkdir -p "$dir"
  if [[ "$role" == facilitator ]]; then
    cat >"$dir/config" <<EOF
[reticulum]
enable_transport = True
share_instance = No
probe_port = 4343

[interfaces]
  [[TCP Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = 4965
EOF
  else
    cat >"$dir/config" <<EOF
[reticulum]
enable_transport = False
share_instance = No
probe_addr = $PROBE_ADDR
direct_connect_policy = accept_all
direct_connect_allow_private_endpoints = yes

[interfaces]
  [[TCP Client]]
    type = TCPClientInterface
    enabled = yes
    target_host = $FAC_IP
    target_port = 4965
EOF
  fi
  in_ns "$ns" env RUST_LOG=info rns-ctl http --config "$dir" --disable-auth \
    --host 127.0.0.1 --port 8080 >"$dir/log" 2>&1 &
  PIDS+=("$!")
}

wait_healthy() {
  local ns
  for ns in "$@"; do
    poll "$ns" /health .status healthy 30 || return 1
  done
}

# channel NS_FROM NS_TO LINK TEXT — send a channel message, check arrival.
channel() {
  local from="$1" to="$2" link="$3" text="$4" data
  data=$(printf '%s' "$text" | base64)
  api_post "$from" /api/channel \
    "$(jq -n --arg l "$link" --arg d "$data" '{link_id: $l, msgtype: 1, payload: $d}')" \
    >/dev/null || return 1
  local deadline=$((SECONDS + 10))
  while ((SECONDS < deadline)); do
    if api_get "$to" /api/packets 2>/dev/null |
      jq -e --arg d "$data" '[.packets[] | select(.data_base64 == $d)] | length > 0' \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

dump_logs() {
  local ns
  for ns in fac "$@"; do
    echo "    --- $ns log (last 25 lines) ---"
    tail -n 25 "$WORK/$ns/log" 2>/dev/null | sed 's/^/    /'
  done
}

# run_case NAME A_NAT B_NAT LAYOUT EXPECT [A_CANDIDATE B_CANDIDATE]
#   LAYOUT: two-nats, same-lan or ipv6 (two-nats over IPv6). EXPECT: direct or transport. The
#   candidates are the kinds of the peer's address each side's direct path
#   must use.
run_case() {
  local name="$1" a_nat="$2" b_nat="$3" layout="$4" expect="$5"
  local a_candidate="${6:-}" b_candidate="${7:-}"
  echo ""
  echo "=== $name: A $a_nat, B $b_nat ($layout), expect $expect ==="
  teardown
  rm -rf "$WORK"
  mkdir -p "$WORK"
  ip link add br-inet type bridge
  ip link set br-inet up
  on_internet fac "$FAC_IP"
  router ra 172.29.0.10 172.29.1
  if [[ "$layout" == same-lan ]]; then
    lan_host ha ra 172.29.1.2 172.29.1
    lan_host hb ra 172.29.1.3 172.29.1
    nat ra "$a_nat" 172.29.1.2 || return
  else
    router rb 172.29.0.20 172.29.2
    lan_host ha ra 172.29.1.2 172.29.1
    lan_host hb rb 172.29.2.2 172.29.2
    nat ra "$a_nat" 172.29.1.2 || return
    nat rb "$b_nat" 172.29.2.2 || return
  fi
  PROBE_ADDR="$FAC_IP:4343"
  if [[ "$layout" == ipv6 ]]; then
    ipv6_nat66 || return
    PROBE_ADDR="[$FAC_IP6]:4343"
  fi

  start_node fac facilitator
  start_node ha peer
  start_node hb peer
  if ! wait_healthy fac ha hb; then
    fail "$name: nodes healthy"
    dump_logs ha hb
    return
  fi
  sleep 2

  local dest link
  dest=$(api_post ha /api/destination \
    '{"type":"single","app_name":"natmatrix","aspects":["case"],"direction":"in","proof_strategy":"none"}' |
    jq -r .dest_hash)
  # Announce until B has it: the first may leave before A's TCP link to the
  # facilitator is up.
  local learned=false attempt
  for attempt in 1 2 3 4 5 6; do
    api_post ha /api/announce "$(jq -n --arg d "$dest" '{dest_hash: $d}')" >/dev/null
    if poll hb "/api/identity/$dest" .dest_hash "$dest" 5 2>/dev/null; then
      learned=true
      break
    fi
  done
  if ! $learned; then
    fail "$name: B learns A's destination"
    dump_logs ha hb
    return
  fi
  link=$(api_post hb /api/link "$(jq -n --arg d "$dest" '{dest_hash: $d}')" | jq -r .link_id)
  if ! poll hb /api/links ".links[] | select(.link_id == \"$link\") | .state" active 30; then
    fail "$name: link active"
    dump_logs ha hb
    return
  fi

  api_post hb /api/direct_connect "$(jq -n --arg l "$link" '{link_id: $l}')" >/dev/null
  local outcome="" deadline=$((SECONDS + 45))
  while ((SECONDS < deadline)); do
    outcome=$(api_get hb /api/link_events 2>/dev/null | jq -r --arg l "$link" \
      '[.link_events[] | select(.link_id == $l and
        (.event_type == "direct_established" or .event_type == "direct_failed"))]
       | last | .event_type // ""' 2>/dev/null) || true
    [[ -n "$outcome" ]] && break
    sleep 1
  done

  local ok=true
  if [[ "$expect" == direct ]]; then
    if [[ "$outcome" != direct_established ]]; then
      fail "$name: upgrades to a direct path" "got '${outcome:-nothing}'"
      ok=false
    elif ! poll ha /api/direct_links \
      ".links[] | select(.link_id == \"$link\") | .path" direct 15; then
      fail "$name: both sides on the direct path"
      ok=false
    else
      pass "$name: upgrades to a direct path"
      local used ns candidate
      for ns in ha hb; do
        candidate=$a_candidate
        [[ "$ns" == hb ]] && candidate=$b_candidate
        used=$(api_get "$ns" /api/direct_links | jq -r --arg l "$link" \
          '.links[] | select(.link_id == $l) | .direct.candidate')
        if [[ -z "$candidate" || "$used" == "$candidate" ]]; then
          pass "$name: $ns uses its peer's ${used} candidate"
        else
          fail "$name: $ns uses its peer's $candidate candidate" "got '$used'"
          ok=false
        fi
        if [[ "$layout" == ipv6 ]]; then
          used=$(api_get "$ns" /api/direct_links | jq -r --arg l "$link" \
            '.links[] | select(.link_id == $l) | .direct.peer_addr')
          if [[ "$used" == "[fd29::"* ]]; then
            pass "$name: $ns reaches its peer over IPv6 at $used"
          else
            fail "$name: $ns reaches its peer over IPv6" "got '$used'"
            ok=false
          fi
        fi
      done
    fi
  else
    if [[ "$outcome" == direct_failed ]]; then
      pass "$name: stays on the transport path"
    else
      fail "$name: stays on the transport path" "got '${outcome:-nothing}'"
      ok=false
    fi
    local path
    path=$(api_get hb /api/direct_links | jq -r --arg l "$link" \
      '.links[] | select(.link_id == $l) | .path')
    if [[ "$path" == transport ]]; then
      pass "$name: B reports the transport path"
    else
      fail "$name: B reports the transport path" "got '$path'"
      ok=false
    fi
  fi

  if channel hb ha "$link" "b-to-a-$name" && channel ha hb "$link" "a-to-b-$name"; then
    pass "$name: link carries messages both ways"
  else
    fail "$name: link carries messages both ways"
    ok=false
  fi
  $ok || dump_logs ha hb
}

CASES=("$@")
if ((${#CASES[@]} == 0)); then
  CASES=(full-cone restricted port-restricted symmetric symmetric-full-cone
    symmetric-restricted same-lan ipv6)
fi

for c in "${CASES[@]}"; do
  case "$c" in
    full-cone) run_case "$c" full-cone port-restricted two-nats direct reflexive reflexive ;;
    restricted) run_case "$c" restricted port-restricted two-nats direct reflexive reflexive ;;
    port-restricted)
      run_case "$c" port-restricted port-restricted two-nats direct reflexive reflexive
      ;;
    symmetric) run_case "$c" symmetric port-restricted two-nats transport ;;
    # A's symmetric NAT gives its punches another port than its probe's:
    # B learns it as a peer-reflexive candidate.
    symmetric-full-cone)
      run_case "$c" symmetric full-cone two-nats direct reflexive peer_reflexive
      ;;
    symmetric-restricted)
      run_case "$c" symmetric restricted two-nats direct reflexive peer_reflexive
      ;;
    # Port-restricted NAT and NAT66 on both sides, reflected and punched
    # over IPv6.
    ipv6) run_case "$c" port-restricted port-restricted ipv6 direct reflexive reflexive ;;
    same-lan) run_case "$c" port-restricted port-restricted same-lan direct host host ;;
    *) fail "unknown case $c" ;;
  esac
done
teardown

echo ""
echo "=== nat-matrix: $PASSES passed, $FAILURES failed ==="
((FAILURES == 0))
