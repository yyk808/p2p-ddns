#!/bin/bash
#
# Single-machine integration test runner for p2p-ddns.
#
# This is a stable entry point that delegates to the Docker topology matrix:
# - scripts/p2p-matrix.sh: runs cases with isolated Docker networks
# - scripts/test-scenarios.sh: maps high-level scenarios to matrix cases

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$SCRIPT_DIR"

log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SINGLE:${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] SINGLE WARNING:${NC} $*"; }
err() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] SINGLE ERROR:${NC} $*" >&2; }
header() { echo -e "${PURPLE}=== $1 ===${NC}"; }

require_docker() {
  command -v docker >/dev/null 2>&1 || { err "docker not found"; exit 1; }
  docker info >/dev/null 2>&1 || { err "docker daemon not reachable"; exit 1; }

  if docker compose version >/dev/null 2>&1; then
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    return 0
  fi
  err "docker compose (plugin) or docker-compose (v1) is required"
  exit 1
}

images_built() {
  docker image inspect p2p-ddns-test-base:test >/dev/null 2>&1
}

build_images() {
  header "Building Images"
  "$INTEGRATION_DIR/scripts/build-images-simple.sh" build --tag test
}

full_test() {
  header "Full Matrix"
  require_docker
  if ! images_built; then
    build_images
  else
    log "Images already built (tag: test), skipping build"
  fi
  "$INTEGRATION_DIR/scripts/p2p-matrix.sh" --no-build
}

scenario_test() {
  local scenario="${1:?missing scenario}"
  header "Scenario: $scenario"
  require_docker
  if ! images_built; then
    build_images
  fi
  "$INTEGRATION_DIR/scripts/test-scenarios.sh" --scenario "$scenario"
}

cleanup() {
  header "Cleanup"
  require_docker
  "$INTEGRATION_DIR/quick-test.sh" clean
}

show_usage() {
  cat <<'EOF'
Usage: single-machine-test.sh [COMMAND]

Commands:
  full                    Build (if needed) + run the default matrix suite
  scenario NAME           Run a scenario via scripts/test-scenarios.sh
  cleanup                 Remove leftover matrix Docker resources
  help

Scenarios:
  basic-functionality
  network-topology
  fault-recovery
EOF
}

case "${1:-help}" in
  full) full_test ;;
  scenario)
    [[ -n "${2:-}" ]] || { err "scenario name required"; show_usage; exit 2; }
    scenario_test "$2"
    ;;
  cleanup) cleanup ;;
  help|--help|-h) show_usage ;;
  *)
    err "Unknown command: ${1:-}"
    show_usage
    exit 2
    ;;
esac

