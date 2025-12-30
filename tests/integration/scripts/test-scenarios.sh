#!/bin/bash
#
# Scenario runner for p2p-ddns integration tests.
#
# This is a thin wrapper around `scripts/p2p-matrix.sh` so existing entry points
# (quick-test.sh, single-machine-test.sh) stay usable.

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SCENARIO:${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] SCENARIO WARNING:${NC} $*"; }
err() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] SCENARIO ERROR:${NC} $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: test-scenarios.sh --scenario NAME [options]

Options:
  --scenario NAME       basic-functionality|network-topology|fault-recovery
  --timeout SECONDS     Default: 300
  --log-level LEVEL     Accepted for compatibility (ignored)
  --list                List available scenarios
  --help
EOF
}

list() {
  cat <<'EOF'
basic-functionality
network-topology
fault-recovery
EOF
}

main() {
  local scenario=""
  local timeout="300"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --scenario) scenario="${2:?missing --scenario value}"; shift 2 ;;
      --timeout) timeout="${2:?missing --timeout value}"; shift 2 ;;
      --log-level) shift 2 ;; # ignored; matrix uses fixed per-role log levels
      --list) list; exit 0 ;;
      --help|-h) usage; exit 0 ;;
      *) err "unknown arg: $1"; usage; exit 2 ;;
    esac
  done

  [[ -n "$scenario" ]] || { err "--scenario is required"; usage; exit 2; }

  case "$scenario" in
    basic-functionality)
      log "Running basic functionality (flat topology)"
      "$INTEGRATION_DIR/scripts/p2p-matrix.sh" --case flat-4 --timeout "$timeout" --no-build
      ;;
    network-topology)
      log "Running network topology matrix (multi-subnet)"
      "$INTEGRATION_DIR/scripts/p2p-matrix.sh" --case two-subnet-3x3 --timeout "$timeout" --no-build
      "$INTEGRATION_DIR/scripts/p2p-matrix.sh" --case two-subnet-gw --timeout "$timeout" --no-build
      "$INTEGRATION_DIR/scripts/p2p-matrix.sh" --case three-subnet-2x2x2 --timeout "$timeout" --no-build
      ;;
    fault-recovery)
      log "Running fault recovery (partition + reconnect)"
      "$INTEGRATION_DIR/scripts/p2p-matrix.sh" --case partition-recover --timeout "$timeout" --no-build
      ;;
    *)
      err "unknown scenario: $scenario"
      list
      exit 2
      ;;
  esac

  warn "Scenario '$scenario' completed"
}

main "$@"
