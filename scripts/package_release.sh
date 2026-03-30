#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
package_release.sh

Stage and archive release artifacts for a target triple.

Env vars:
  TARGET    Optional target triple (default: rustc host triple)
  VERSION   Optional version string (default: Cargo.toml version)
  OUT_DIR   Optional output directory (default: dist/release)
  BIN_DIR   Optional directory containing built binaries

Examples:
  cargo build --release --bins
  scripts/package_release.sh

  cargo build --release --bins --target aarch64-apple-darwin
  TARGET=aarch64-apple-darwin VERSION=0.2.0 scripts/package_release.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_NAME="p2p-ddns"
TARGET="${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
VERSION="${VERSION:-}"
if [[ -z "${VERSION}" ]]; then
  VERSION="$(awk -F '\"' '/^version = / {print $2; exit}' "${ROOT}/Cargo.toml")"
fi

VERSION="${VERSION#v}"
OUT_DIR="${OUT_DIR:-${ROOT}/dist/release}"
BIN_DIR="${BIN_DIR:-${ROOT}/target/${TARGET}/release}"
ARCHIVE_STEM="${PACKAGE_NAME}-v${VERSION}-${TARGET}"
STAGE_DIR="${OUT_DIR}/${ARCHIVE_STEM}"

if [[ ! -d "${BIN_DIR}" && -d "${ROOT}/target/release" ]]; then
  BIN_DIR="${ROOT}/target/release"
fi

case "${TARGET}" in
  *-pc-windows-*)
    BIN_EXT=".exe"
    ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_STEM}.zip"
    ;;
  *)
    BIN_EXT=""
    ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_STEM}.tar.gz"
    ;;
esac

for bin in p2p-ddns p2p-ddnsctl; do
  if [[ ! -f "${BIN_DIR}/${bin}${BIN_EXT}" ]]; then
    echo "built binary not found: ${BIN_DIR}/${bin}${BIN_EXT}" >&2
    exit 1
  fi
done

rm -rf "${STAGE_DIR}" "${ARCHIVE_PATH}"
mkdir -p "${STAGE_DIR}"

install -m 0755 "${BIN_DIR}/p2p-ddns${BIN_EXT}" "${STAGE_DIR}/p2p-ddns${BIN_EXT}"
install -m 0755 "${BIN_DIR}/p2p-ddnsctl${BIN_EXT}" "${STAGE_DIR}/p2p-ddnsctl${BIN_EXT}"
install -m 0644 "${ROOT}/README.md" "${STAGE_DIR}/README.md"
install -m 0644 "${ROOT}/LICENCE" "${STAGE_DIR}/LICENCE"

if [[ "${TARGET}" == *-linux-* ]]; then
  mkdir -p "${STAGE_DIR}/packaging"
  cp -R "${ROOT}/packaging/systemd" "${STAGE_DIR}/packaging/systemd"
fi

mkdir -p "${OUT_DIR}"

case "${ARCHIVE_PATH}" in
  *.tar.gz)
    tar -C "${OUT_DIR}" -czf "${ARCHIVE_PATH}" "${ARCHIVE_STEM}"
    ;;
  *.zip)
    if ! command -v zip >/dev/null 2>&1; then
      echo "zip not found; install zip to build Windows archives" >&2
      exit 1
    fi
    (
      cd "${OUT_DIR}"
      zip -qr "${ARCHIVE_PATH}" "${ARCHIVE_STEM}"
    )
    ;;
esac

rm -rf "${STAGE_DIR}"

echo "Built: ${ARCHIVE_PATH}"
