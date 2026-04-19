#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

VPS_HOST="${VPS_HOST:-vps-eu}"
VPS_BIN="${VPS_BIN:-/usr/local/bin/rns-bisect}"
VPS_CONFIG_DIR="${VPS_CONFIG_DIR:-/tmp/rns-bisect-reticulum}"
VPS_LOG="${VPS_LOG:-/tmp/rns-bisect.out}"
VPS_PROVIDER_SOCK="${VPS_PROVIDER_SOCK:-/run/rns/provider-bisect.sock}"

SHARED_PORT="${SHARED_PORT:-47428}"
RPC_PORT="${RPC_PORT:-47429}"
BACKBONE_PORT="${BACKBONE_PORT:-5242}"
PROBE_PORT="${PROBE_PORT:-5343}"

commit="$(git rev-parse --short HEAD)"
echo "==> bisect commit: $commit"

build_daemon() {
  if [[ -f rns-ctl/Cargo.toml ]]; then
    echo "==> building rns-ctl daemon target"
    cargo build --release -p rns-ctl --features rns-hooks >/dev/null 2>&1 || return 125
    LOCAL_BIN="target/release/rns-ctl"
    RUN_MODE="ctl"
    return 0
  fi

  if [[ -f rns-cli/Cargo.toml ]] && rg -q '^name = "rnsd"$' rns-cli/Cargo.toml; then
    echo "==> building rnsd binary"
    cargo build --release -p rns-cli --bin rnsd >/dev/null 2>&1 || return 125
    LOCAL_BIN="target/release/rnsd"
    RUN_MODE="rnsd"
    return 0
  fi

  echo "==> no supported daemon target in this commit, skipping"
  return 125
}

prepare_vps_config() {
  ssh "$VPS_HOST" bash -lc "'
    set -euo pipefail
    rm -rf \"$VPS_CONFIG_DIR\"
    mkdir -p \"$VPS_CONFIG_DIR\"
    cp /root/.reticulum/config \"$VPS_CONFIG_DIR/config\"
    perl -0pi -e \"s/\\[reticulum\\]\\n/[reticulum]\\nshared_instance_port = $SHARED_PORT\\ninstance_control_port = $RPC_PORT\\n/; s/probe_port\\s*=\\s*\\d+/probe_port = $PROBE_PORT/; s#provider_socket_path\\s*=\\s*.*#provider_socket_path = $VPS_PROVIDER_SOCK#; s/listen_port\\s*=\\s*4242/listen_port = $BACKBONE_PORT/\" \"$VPS_CONFIG_DIR/config\"
    rm -f \"$VPS_PROVIDER_SOCK\" \"$VPS_LOG\" \"$VPS_BIN\"
  '"
}

upload_binary() {
  echo "==> uploading test binary to $VPS_HOST:$VPS_BIN"
  ssh "$VPS_HOST" "cat > '$VPS_BIN'" < "$LOCAL_BIN"
  ssh "$VPS_HOST" "chmod 755 '$VPS_BIN'"
}

run_remote_probe() {
  local remote_cmd
  if [[ "$RUN_MODE" == "ctl" ]]; then
    remote_cmd="'$VPS_BIN' daemon -c '$VPS_CONFIG_DIR'"
  else
    remote_cmd="'$VPS_BIN' -c '$VPS_CONFIG_DIR'"
  fi

  echo "==> starting isolated VPS daemon probe"
  ssh "$VPS_HOST" bash -lc "'
    set -euo pipefail
    timeout 12 $remote_cmd >\"$VPS_LOG\" 2>&1 &
    pid=\$!
    found=1
    listeners=
    unixs=
    for _ in \$(seq 1 10); do
      listeners=\$(ss -ltnp || true)
      unixs=\$(ss -lxp || true)
      if grep -qE \":$SHARED_PORT([[:space:]]|$)\" <<<\"\$listeners\" &&
         grep -qE \":$RPC_PORT([[:space:]]|$)\" <<<\"\$listeners\"; then
        found=0
        break
      fi
      sleep 1
    done
    wait \$pid || true

    echo \"\$listeners\"
    echo ---UNIX---
    echo \"\$unixs\"
    echo ---LOG---
    sed -n \"1,120p\" \"$VPS_LOG\" || true

    if [[ \$found -eq 0 ]]; then
      exit 0
    fi

    exit 1
  '"
}

if ! build_daemon; then
  exit $?
fi

prepare_vps_config
upload_binary
run_remote_probe
