#!/usr/bin/env bash
# Build and run the privileged Linux-to-Linux rntun acceptance suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

NO_TEARDOWN=false
CLEAN_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-teardown) NO_TEARDOWN=true; shift ;;
    --clean) CLEAN_ONLY=true; shift ;;
    *) echo "Usage: $0 [--no-teardown] [--clean]" >&2; exit 1 ;;
  esac
done

for command in docker jq; do
  command -v "$command" >/dev/null || {
    echo "ERROR: '$command' is required but not found." >&2
    exit 1
  }
done
docker compose version >/dev/null || {
  echo "ERROR: 'docker compose' (v2) is required." >&2
  exit 1
}

cleanup() {
  if ! $NO_TEARDOWN; then
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if $CLEAN_ONLY; then
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
  exit 0
fi

if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
  echo "=== Building rns-test image with rntun ==="
  docker build -t rns-test -f "${REPO_ROOT}/tests/docker/Dockerfile" "$REPO_ROOT"
fi

echo "=== Starting rntun Linux acceptance topology ==="
docker compose -f "$COMPOSE_FILE" up -d --wait

result=0
bash "${SCRIPT_DIR}/test.sh" || result=$?
if (( result != 0 )); then
  echo ""
  echo "=== rntun container logs ==="
  docker compose -f "$COMPOSE_FILE" logs --tail=200 || true
  for container in rntun-gateway rntun-client; do
    echo "--- ${container} process log ---"
    docker exec "$container" sh -c 'cat /tmp/rntun-*.log 2>/dev/null' || true
  done
fi
exit "$result"
