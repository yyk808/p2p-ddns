#!/bin/bash
#
# Quick wrapper for the Docker-based integration matrix.
#
# The underlying runner is `scripts/p2p-matrix.sh` which generates docker compose
# files per case and cleans up by default.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] QUICK:${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] QUICK WARNING:${NC} $*"; }
err() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] QUICK ERROR:${NC} $*" >&2; }
header() { echo -e "${PURPLE}=== $1 ===${NC}"; }
info() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] QUICK:${NC} $*"; }

show_usage() {
  cat <<'EOF'
Usage: quick-test.sh [COMMAND] [OPTIONS]

Commands:
  quick           Smoke test (flat topology)
  full            Full suite (basic + topology + partition)
  basic           Basic functionality scenario
  network         Network topology scenario
  fault           Fault recovery scenario
  build           Build Docker images (tag: test)
  clean           Remove leftover matrix Docker resources
  help

Options:
  --timeout SECS  Default: 300
  --debug         Accepted for compatibility (ignored)
  --no-build      Skip building images
EOF
}

require_docker() {
  command -v docker >/dev/null 2>&1 || { err "docker not found"; exit 1; }
  docker info >/dev/null 2>&1 || { err "docker daemon not reachable"; exit 1; }
}

parse_args() {
  COMMAND=""
  TIMEOUT="300"
  BUILD_IMAGES="true"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --timeout) TIMEOUT="${2:?missing --timeout value}"; shift 2 ;;
      --debug) shift ;; # ignored; p2p-matrix uses fixed per-role log levels
      --no-build) BUILD_IMAGES="false"; shift ;;
      help|--help|-h) show_usage; exit 0 ;;
      quick|full|basic|network|fault|build|clean)
        [[ -z "$COMMAND" ]] || { err "multiple commands specified"; exit 2; }
        COMMAND="$1"
        shift
        ;;
      *) err "unknown arg: $1"; show_usage; exit 2 ;;
    esac
  done

  [[ -n "$COMMAND" ]] || COMMAND="quick"
}

cmd_build() {
  header "Building Docker Images"
  require_docker
  if [[ "$BUILD_IMAGES" == "true" ]]; then
    "$SCRIPT_DIR/scripts/build-images-simple.sh" build --tag test
  else
    info "Skipping image build (--no-build)"
  fi
}

cmd_clean() {
  header "Cleaning Matrix Resources"
  require_docker

  local removed="0"

  while read -r id name; do
    [[ -n "${id:-}" && -n "${name:-}" ]] || continue
    if [[ "$name" == p2pddns_it_* ]]; then
      docker rm -f "$id" >/dev/null 2>&1 || true
      removed=$((removed + 1))
    fi
  done < <(docker ps -a --format '{{.ID}} {{.Names}}')

  while read -r id name; do
    [[ -n "${id:-}" && -n "${name:-}" ]] || continue
    if [[ "$name" == p2pddns_it_* ]]; then
      docker network rm "$id" >/dev/null 2>&1 || true
    fi
  done < <(docker network ls --format '{{.ID}} {{.Name}}')

  while read -r name; do
    [[ -n "${name:-}" ]] || continue
    if [[ "$name" == p2pddns_it_*_tickets ]]; then
      docker volume rm "$name" >/dev/null 2>&1 || true
    fi
  done < <(docker volume ls --format '{{.Name}}')

  log "Cleanup done (removed containers: $removed)"
}

run_scenario() {
  local scenario="$1"
  "$SCRIPT_DIR/scripts/test-scenarios.sh" --scenario "$scenario" --timeout "$TIMEOUT"
}

main() {
  parse_args "$@"

  case "$COMMAND" in
    build) cmd_build ;;
    clean) cmd_clean ;;
    quick)
      header "Quick Smoke Test"
      cmd_build
      run_scenario basic-functionality
      ;;
    basic)
      header "Basic Functionality"
      cmd_build
      run_scenario basic-functionality
      ;;
    network)
      header "Network Topology"
      cmd_build
      run_scenario network-topology
      ;;
    fault)
      header "Fault Recovery"
      cmd_build
      run_scenario fault-recovery
      ;;
    full)
      header "Full Suite"
      cmd_build
      run_scenario basic-functionality
      run_scenario network-topology
      run_scenario fault-recovery
      ;;
    *) err "unknown command: $COMMAND"; exit 2 ;;
  esac
}

main "$@"
