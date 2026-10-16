#!/bin/sh
# Entrypoint for the Python Reticulum containers of the shared-instance-links
# test (issue #183). Copies the read-only config into a writable directory
# and runs the HTTP control server.
#   $1: control server port (default 8080)
set -e

mkdir -p /data/rns
cp /etc/rns/config /data/rns/config
exec python3 /usr/local/bin/rns_e2e_control.py \
  --config /data/rns --port "${1:-8080}" --app-name e2esil
