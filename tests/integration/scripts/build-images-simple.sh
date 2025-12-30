#!/bin/bash

# Build script for p2p-ddns integration test Docker images.
#
# Builds:
# - p2p-ddns-test-base:latest (+ optional additional tag)
# - p2p-ddns-test-primary:<tag>
# - p2p-ddns-test-daemon:<tag>
# - p2p-ddns-test-client:<tag>
#
# The node Dockerfiles currently reference the base image tag ":latest".

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$INTEGRATION_DIR/../.." && pwd)"

log() { echo "[build-images] $*"; }
err() { echo "[build-images] ERROR: $*" >&2; }

usage() {
  cat <<'EOF'
Usage: build-images-simple.sh {build|build-base|build-node|list|remove|help} [options]

Options:
  --tag TAG        Tag for node images (default: test)
  --node TYPE      Node type for build-node (primary|daemon|client)
  --with-client    Also build the client image in `build` (default: off)

Examples:
  ./scripts/build-images-simple.sh build --tag test
  ./scripts/build-images-simple.sh build-base
  ./scripts/build-images-simple.sh build-node --node daemon --tag test
EOF
}

require_docker() {
  command -v docker >/dev/null 2>&1 || { err "docker not found"; exit 1; }
  docker version >/dev/null 2>&1 || { err "docker daemon not reachable"; exit 1; }
  export DOCKER_BUILDKIT=1
}

build_base() {
  local tag="${1:-test}"
  require_docker

  log "Building base image: p2p-ddns-test-base:latest"
  docker build \
    -f "$INTEGRATION_DIR/nodes/base/Dockerfile" \
    -t "p2p-ddns-test-base:latest" \
    -t "p2p-ddns-test-base:${tag}" \
    "$PROJECT_ROOT"
}

build_node() {
  local node_type="$1"
  local tag="${2:-test}"

  require_docker

  case "$node_type" in
    primary|daemon|client) ;;
    *) err "unknown node type: $node_type"; exit 1 ;;
  esac

  log "Building node image: p2p-ddns-test-${node_type}:${tag}"
  docker build \
    -f "$INTEGRATION_DIR/nodes/${node_type}/Dockerfile" \
    -t "p2p-ddns-test-${node_type}:${tag}" \
    "$PROJECT_ROOT"
}

list_images() {
  require_docker
  docker image ls --format '{{.Repository}}:{{.Tag}}' | rg -n '^p2p-ddns-test-' || true
}

remove_images() {
  require_docker
  local images
  images="$(docker image ls --format '{{.Repository}}:{{.Tag}}' | rg -n '^p2p-ddns-test-' || true)"
  if [[ -z "$images" ]]; then
    log "No p2p-ddns-test-* images to remove"
    return 0
  fi
  log "Removing images:"
  echo "$images"
  # shellcheck disable=SC2086
  docker rmi -f $images || true
}

main() {
  local cmd="${1:-help}"
  shift || true

  local tag="test"
  local node=""
  local with_client="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag) tag="${2:?missing --tag value}"; shift 2 ;;
      --node) node="${2:?missing --node value}"; shift 2 ;;
      --with-client) with_client="true"; shift ;;
      *) err "unknown option: $1"; usage; exit 2 ;;
    esac
  done

  case "$cmd" in
    build)
      build_base "$tag"
      build_node primary "$tag"
      build_node daemon "$tag"
      if [[ "$with_client" == "true" ]]; then
        build_node client "$tag"
      else
        log "Skipping client image (pass --with-client to build it)"
      fi
      ;;
    build-base)
      build_base "$tag"
      ;;
    build-node)
      [[ -n "$node" ]] || { err "--node is required for build-node"; exit 2; }
      build_node "$node" "$tag"
      ;;
    list) list_images ;;
    remove) remove_images ;;
    help|--help|-h) usage ;;
    *) err "unknown command: $cmd"; usage; exit 2 ;;
  esac
}

main "$@"
