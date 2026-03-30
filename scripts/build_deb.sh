#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
build_deb.sh

Build a simple .deb package for Ubuntu/Debian that installs:
  - /usr/bin/p2p-ddns
  - /usr/bin/p2p-ddnsctl
  - /usr/lib/p2p-ddns/p2p-ddns-wrapper
  - /lib/systemd/system/p2p-ddns.service
  - /etc/default/p2p-ddns (conffile)

Requirements (on the build machine):
  - cargo (Rust toolchain), or cross (for cross-compiling)
  - dpkg-deb (optional; will fall back to Docker if unavailable)

Env vars:
  BUILDER       auto|cargo|cross (default: auto)
  TARGET        Optional cargo target triple (e.g. x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu)
  FEATURES      Optional cargo features (e.g. "pkarr-dht")
  DEB_ARCH      Optional deb architecture (default: dpkg --print-architecture)
  DEB_VERSION   Optional package version (default: Cargo.toml version)
  MAINTAINER    Optional maintainer (default: "p2p-ddns <root@localhost>")
  OUT_DIR       Optional output directory (default: dist/deb)

Examples:
  scripts/build_deb.sh
  # Build an amd64 musl package from macOS/Windows using cross (Docker required):
  TARGET=x86_64-unknown-linux-musl DEB_ARCH=amd64 BUILDER=cross scripts/build_deb.sh
  TARGET=aarch64-unknown-linux-gnu DEB_ARCH=arm64 BUILDER=cross scripts/build_deb.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found (install Rust toolchain)" >&2
  exit 1
fi

DEB_NAME="p2p-ddns"

DEB_VERSION="${DEB_VERSION:-}"
if [[ -z "${DEB_VERSION}" ]]; then
  DEB_VERSION="$(awk -F '\"' '/^version = / {print $2; exit}' "${ROOT}/Cargo.toml")"
fi
DEB_VERSION="${DEB_VERSION#v}"

DEB_ARCH="${DEB_ARCH:-}"
if [[ -z "${DEB_ARCH}" ]] && command -v dpkg >/dev/null 2>&1; then
  DEB_ARCH="$(dpkg --print-architecture)"
fi

MAINTAINER="${MAINTAINER:-p2p-ddns <root@localhost>}"
OUT_DIR="${OUT_DIR:-${ROOT}/dist/deb}"

BUILDER="${BUILDER:-auto}"
TARGET="${TARGET:-}"
FEATURES="${FEATURES:-}"

HOST_OS="$(uname -s 2>/dev/null || echo unknown)"

# On non-Linux hosts, default to building a Linux binary; otherwise we'd package a macOS/Windows
# binary into a .deb which is useless.
if [[ "${HOST_OS}" != "Linux" && -z "${TARGET}" ]]; then
  TARGET="x86_64-unknown-linux-musl"
fi

if [[ -z "${DEB_ARCH}" ]]; then
  if command -v dpkg >/dev/null 2>&1; then
    DEB_ARCH="$(dpkg --print-architecture)"
  elif [[ -n "${TARGET}" ]]; then
    case "${TARGET}" in
      x86_64-*) DEB_ARCH="amd64" ;;
      aarch64-*) DEB_ARCH="arm64" ;;
      armv7-*) DEB_ARCH="armhf" ;;
      *) echo "DEB_ARCH is not set and cannot infer it from TARGET=${TARGET}" >&2; exit 1 ;;
    esac
  else
    echo "DEB_ARCH is not set and dpkg is unavailable; set DEB_ARCH explicitly." >&2
    exit 1
  fi
fi

if [[ "${BUILDER}" == "auto" ]]; then
  if [[ -n "${TARGET}" && "${TARGET}" == *-unknown-linux-* && "${HOST_OS}" != "Linux" ]]; then
    BUILDER="cross"
  else
    BUILDER="cargo"
  fi
fi

echo "Building ${DEB_NAME} ${DEB_VERSION} (${DEB_ARCH})"
echo "  host_os=${HOST_OS}"
echo "  builder=${BUILDER}"
echo "  target=${TARGET:-<native>}"

pushd "${ROOT}" >/dev/null

BUILD_ARGS=(build --release)
BUILD_ARGS+=(--bin p2p-ddns --bin p2p-ddnsctl)
if [[ -n "${TARGET}" ]]; then
  BUILD_ARGS+=(--target "${TARGET}")
fi
if [[ -n "${FEATURES}" ]]; then
  BUILD_ARGS+=(--features "${FEATURES}")
fi

case "${BUILDER}" in
  cargo)
    cargo "${BUILD_ARGS[@]}"
    ;;
  cross)
    if [[ -z "${TARGET}" ]]; then
      echo "BUILDER=cross requires TARGET to be set (e.g. x86_64-unknown-linux-musl)" >&2
      exit 2
    fi
    if ! command -v cross >/dev/null 2>&1; then
      echo "cross not found (install: cargo install cross)" >&2
      exit 1
    fi
    cross "${BUILD_ARGS[@]}"
    ;;
  *)
    echo "invalid BUILDER=${BUILDER} (expected: auto|cargo|cross)" >&2
    exit 2
    ;;
esac

BIN_PATH=""
CTL_PATH=""
if [[ -n "${TARGET}" ]]; then
  BIN_PATH="${ROOT}/target/${TARGET}/release/p2p-ddns"
  CTL_PATH="${ROOT}/target/${TARGET}/release/p2p-ddnsctl"
else
  BIN_PATH="${ROOT}/target/release/p2p-ddns"
  CTL_PATH="${ROOT}/target/release/p2p-ddnsctl"
fi

if [[ ! -x "${BIN_PATH}" ]]; then
  echo "built binary not found: ${BIN_PATH}" >&2
  exit 1
fi

if [[ ! -x "${CTL_PATH}" ]]; then
  echo "built binary not found: ${CTL_PATH}" >&2
  exit 1
fi

PKG_ROOT="${OUT_DIR}/${DEB_NAME}_${DEB_VERSION}_${DEB_ARCH}"
STAGE="${PKG_ROOT}/rootfs"

rm -rf "${PKG_ROOT}"
mkdir -p "${STAGE}/DEBIAN" \
  "${STAGE}/usr/bin" \
  "${STAGE}/usr/lib/${DEB_NAME}" \
  "${STAGE}/lib/systemd/system" \
  "${STAGE}/etc/default"

install -m 0755 "${BIN_PATH}" "${STAGE}/usr/bin/p2p-ddns"
install -m 0755 "${CTL_PATH}" "${STAGE}/usr/bin/p2p-ddnsctl"
install -m 0755 "${ROOT}/packaging/systemd/p2p-ddns-wrapper" "${STAGE}/usr/lib/${DEB_NAME}/p2p-ddns-wrapper"
install -m 0644 "${ROOT}/packaging/systemd/p2p-ddns.service" "${STAGE}/lib/systemd/system/p2p-ddns.service"
install -m 0644 "${ROOT}/packaging/systemd/p2p-ddns.default" "${STAGE}/etc/default/p2p-ddns"

cat >"${STAGE}/DEBIAN/control" <<EOF
Package: ${DEB_NAME}
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: ${MAINTAINER}
Description: p2p-ddns peer-to-peer DDNS daemon
 A self-hosted P2P-based dynamic DNS helper built on iroh + gossip.
EOF

cat >"${STAGE}/DEBIAN/conffiles" <<'EOF'
/etc/default/p2p-ddns
EOF

cat >"${STAGE}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

ensure_group() {
  if getent group p2p-ddns >/dev/null 2>&1; then
    return 0
  fi
  if command -v addgroup >/dev/null 2>&1; then
    addgroup --system p2p-ddns >/dev/null
  else
    groupadd -r p2p-ddns >/dev/null 2>&1 || true
  fi
}

ensure_user() {
  if id -u p2p-ddns >/dev/null 2>&1; then
    return 0
  fi
  if command -v adduser >/dev/null 2>&1; then
    adduser --system --home /var/lib/p2p-ddns --no-create-home --ingroup p2p-ddns --shell /usr/sbin/nologin p2p-ddns >/dev/null
  else
    useradd -r -g p2p-ddns -d /var/lib/p2p-ddns -s /usr/sbin/nologin p2p-ddns >/dev/null 2>&1 || true
  fi
}

ensure_group
ensure_user

mkdir -p /var/lib/p2p-ddns
chown -R p2p-ddns:p2p-ddns /var/lib/p2p-ddns || true

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

echo "p2p-ddns installed."
echo "Edit /etc/default/p2p-ddns then run:"
echo "  sudo systemctl enable --now p2p-ddns"

exit 0
EOF
chmod 0755 "${STAGE}/DEBIAN/postinst"

cat >"${STAGE}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop p2p-ddns.service >/dev/null 2>&1 || true
  systemctl disable p2p-ddns.service >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
EOF
chmod 0755 "${STAGE}/DEBIAN/prerm"

DEB_BASENAME="${DEB_NAME}_${DEB_VERSION}_${DEB_ARCH}.deb"
DEB_OUT="${OUT_DIR}/${DEB_BASENAME}"
mkdir -p "${OUT_DIR}"

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build --root-owner-group "${STAGE}" "${DEB_OUT}" >/dev/null
else
  if ! command -v docker >/dev/null 2>&1; then
    echo "dpkg-deb not found and docker is unavailable; install dpkg-deb or provide docker." >&2
    exit 1
  fi
  docker run --rm \
    -v "${STAGE}:/rootfs:ro" \
    -v "${OUT_DIR}:/out" \
    debian:bookworm-slim \
    dpkg-deb --build --root-owner-group /rootfs "/out/${DEB_BASENAME}" >/dev/null
fi

echo "Built: ${DEB_OUT}"

popd >/dev/null
