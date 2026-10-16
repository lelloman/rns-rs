#!/usr/bin/env bash
# Entrypoint for the daemon container of the shared-instance-links test
# (issue #183). Runs, in one network namespace:
#   - rns-ctl daemon: the shared instance (share_instance=Yes,
#     enable_transport=$DAEMON_ENABLE_TRANSPORT, default False) with a TCP
#     server for the external peer
#   - two rns-ctl http --daemon shared clients (A on 8080, B on 8081),
#     each with its own config dir, identity and storage
# The Python sibling joins this namespace via network_mode: service:daemon.
set -euo pipefail

mkdir -p /data/daemon /data/client-a /data/client-b
# DAEMON_ENABLE_TRANSPORT (False/True) selects the daemon's enable_transport.
sed "s/^enable_transport = .*/enable_transport = ${DAEMON_ENABLE_TRANSPORT:-False}/" \
  /etc/rns/daemon/config > /data/daemon/config
echo "Shared instance config:"
cat /data/daemon/config
cp /etc/rns/client/config /data/client-a/config
cp /etc/rns/client/config /data/client-b/config

rns-ctl daemon --config /data/daemon &
DAEMON_PID=$!
echo "Started shared instance daemon with PID ${DAEMON_PID}"

# On Linux the shared instance listens on the abstract Unix socket
# rns/default (shown as @rns/default in /proc/net/unix).
for _ in $(seq 1 60); do
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "ERROR: shared instance daemon exited prematurely" >&2
    exit 1
  fi
  if grep -q '@rns/default$' /proc/net/unix; then
    break
  fi
  sleep 0.5
done
echo "Shared instance socket is up"

rns-ctl http --daemon --config /data/client-a --disable-auth --host 0.0.0.0 --port 8080 &
rns-ctl http --daemon --config /data/client-b --disable-auth --host 0.0.0.0 --port 8081 &

# Exit (and fail the container) as soon as any process dies.
wait -n
echo "ERROR: a process exited" >&2
exit 1
