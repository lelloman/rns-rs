#!/bin/sh
# Entrypoint for the client container.
# Runs rnsd (daemon with share_instance=Yes) in background,
# then rns-ctl http --daemon (shared client) in foreground.
set -e

cp /etc/rns/config /data/config
RNSD_LOG=/tmp/rnsd.log
rm -f "$RNSD_LOG"

# Start rnsd in background
rns-ctl daemon --config /data >>"$RNSD_LOG" 2>&1 &
RNSD_PID=$!
echo "$RNSD_PID" > /tmp/rnsd.pid
echo "Started rnsd with PID $RNSD_PID"

# Wait for rnsd to start accepting shared instance connections. On Linux
# the shared instance listens on the abstract Unix socket rns/default
# (shown as @rns/default in /proc/net/unix), not on TCP 37428.
for i in $(seq 1 60); do
  if ! kill -0 "$RNSD_PID" 2>/dev/null; then
    echo "ERROR: rnsd exited prematurely"
    exit 1
  fi
  if grep -q '@rns/default$' /proc/net/unix; then
    echo "Shared instance socket is up"
    break
  fi
  sleep 0.5
done

# Extra settle time for rnsd to fully initialize
sleep 2

echo "Starting shared client HTTP API..."
exec rns-ctl http --daemon --config /data --disable-auth --host 0.0.0.0 --port 8080
