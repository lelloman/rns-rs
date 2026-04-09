#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
OUTPUT_NAME="rns-server-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
SKIP_BUILD=false

usage() {
  cat <<'EOF'
Usage: package-rns-server-tarball.sh [--output-name NAME] [--skip-build]

Build a single deployable rns-server binary and bundle it into dist/<name>.tar.gz.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-name)
      OUTPUT_NAME="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! $SKIP_BUILD; then
  cargo build --release \
    --bin rns-server \
    --features rns-hooks
fi

rm -rf "${DIST_DIR:?}/${OUTPUT_NAME}"
mkdir -p "${DIST_DIR}/${OUTPUT_NAME}/bin" "${DIST_DIR}/${OUTPUT_NAME}/docs"

cp "${REPO_ROOT}/target/release/rns-server" "${DIST_DIR}/${OUTPUT_NAME}/bin/"

cp "${REPO_ROOT}/docs/rns-server-operator-runbook.md" "${DIST_DIR}/${OUTPUT_NAME}/docs/"

TMP_ARCHIVE="${DIST_DIR}/${OUTPUT_NAME}.tar.gz.tmp"
FINAL_ARCHIVE="${DIST_DIR}/${OUTPUT_NAME}.tar.gz"
rm -f "${TMP_ARCHIVE}" "${FINAL_ARCHIVE}"
tar -C "${DIST_DIR}" -czf "${TMP_ARCHIVE}" "${OUTPUT_NAME}"
mv "${TMP_ARCHIVE}" "${FINAL_ARCHIVE}"
echo "wrote ${FINAL_ARCHIVE}"
