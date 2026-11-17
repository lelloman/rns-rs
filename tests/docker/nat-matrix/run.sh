#!/usr/bin/env bash
# run.sh — Direct Link NAT matrix in one privileged container.
#
# The container has no Docker network (--network none): matrix.sh builds
# every network it needs from namespaces inside it, on 172.29.0.0/16, and
# removes them again. Nothing is created on the host but the container.
#
# Usage: run.sh [--no-teardown] [--clean] [case ...]
#   RNS_TEST_IMAGE   image to run (default rns-test)
#   NAT_MATRIX_NAME  container name (default rns-nat-matrix)
#   SKIP_BUILD=true  use the existing image
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
IMAGE="${RNS_TEST_IMAGE:-rns-test}"
NAME="${NAT_MATRIX_NAME:-rns-nat-matrix}"

NO_TEARDOWN=false
CASES=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-teardown) NO_TEARDOWN=true; shift ;;
    --clean)
      docker rm -f "$NAME" >/dev/null 2>&1 || true
      exit 0
      ;;
    -*)
      echo "Usage: $0 [--no-teardown] [--clean] [case ...]" >&2
      exit 1
      ;;
    *) CASES+=("$1"); shift ;;
  esac
done

if ! command -v docker &>/dev/null; then
  echo "ERROR: 'docker' is required but not found." >&2
  exit 1
fi

if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
  echo "=== Building ${IMAGE} Docker image ==="
  docker build --build-arg CARGO_BUILD_JOBS --build-arg CARGO_PROFILE_RELEASE_CODEGEN_UNITS \
    -t "$IMAGE" -f "${REPO_ROOT}/tests/docker/Dockerfile" "$REPO_ROOT"
fi

teardown() {
  if ! $NO_TEARDOWN; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
  fi
}
trap teardown EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true
# Privileged for network namespaces and iptables; the restricted-cone
# case needs the host kernel's xt_recent module, which the kernel loads
# on demand.
docker run -d --name "$NAME" --privileged --network none \
  -v "${SCRIPT_DIR}:/matrix:ro" --entrypoint sleep "$IMAGE" infinity >/dev/null

OUTPUT="$(mktemp "${TMPDIR:-/tmp}/rns-nat-matrix.XXXXXX")"
trap 'rm -f "$OUTPUT"; teardown' EXIT
set +e
docker exec "$NAME" bash /matrix/matrix.sh "${CASES[@]+"${CASES[@]}"}" | tee "$OUTPUT"
status=${PIPESTATUS[0]}
set -e

# Record results for run-all.sh's summary.
if [[ -n "${TEST_RESULTS_FILE:-}" ]]; then
  sed -n 's/^  \(PASS\|FAIL\): \(.*\)$/\1\tnat-matrix\tnat-matrix\t\2\t/p' "$OUTPUT" \
    >>"$TEST_RESULTS_FILE"
fi
exit "$status"
