#!/bin/bash
#
# P2P topology + scale integration tests (Docker)
#
# Runs p2p-ddns daemons across isolated Docker networks and validates that the
# overlay converges (nodes are visible across subnets) using the admin Unix socket.
#
# This script is intentionally self-contained and does not depend on the legacy
# docker-compose.yml in this directory.

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] MATRIX:${NC} $*"; }
info() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] MATRIX:${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] MATRIX WARNING:${NC} $*"; }
err() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] MATRIX ERROR:${NC} $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

KEEP_TMPDIR="false"
KEEP_PROJECT=""
KEEP_COMPOSE_FILE=""

detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    err "docker compose (plugin) or docker-compose (v1) is required"
    exit 1
  fi
}

usage() {
  cat <<'EOF'
Usage: p2p-matrix.sh [options]

Options:
  --case NAME          Run a single case (default: run default suite)
  --list               List cases
  --timeout SECS       Convergence timeout (default: 180)
  --tag TAG            Image tag (default: test)
  --no-build           Skip image build
  --verify-all         Also verify daemons via their periodic stdout tables
  --keep               Keep containers on failure (default: cleanup)
  --help

Cases:
  flat-2               1 subnet, 2 daemons
  flat-4               1 subnet, 4 daemons
  flat-8               1 subnet, 8 daemons
  two-subnet-3x3       2 subnets, 6 daemons (3 + 3), primary multi-homed
  two-subnet-6x6       2 subnets, 12 daemons (6 + 6), primary multi-homed
  two-subnet-gw        2 subnets + 1 multi-homed daemon (gateway), total 5 daemons
  three-subnet-2x2x2   3 subnets, 6 daemons (2 + 2 + 2), primary multi-homed
  partition-recover    2 subnets (3 + 3), disconnect/reconnect primary from subnet-b
EOF
}

list_cases() {
  cat <<'EOF'
flat-2
flat-4
flat-8
two-subnet-3x3
two-subnet-6x6
two-subnet-gw
three-subnet-2x2x2
partition-recover
EOF
}

require_docker() {
  command -v docker >/dev/null 2>&1 || { err "docker not found"; exit 1; }
  docker info >/dev/null 2>&1 || { err "docker daemon not reachable"; exit 1; }
}

build_images() {
  local tag="$1"
  info "Building images (tag: $tag)..."
  "$INTEGRATION_DIR/scripts/build-images-simple.sh" build --tag "$tag"
}

tmpdir=""
cleanup_tmpdir() {
  if [[ -n "${tmpdir}" && -d "${tmpdir}" ]]; then
    if [[ "${KEEP_TMPDIR}" == "true" ]]; then
      warn "Keeping temp dir for debugging: ${tmpdir}"
      [[ -n "${KEEP_PROJECT}" ]] && warn "Debug project: ${KEEP_PROJECT}"
      [[ -n "${KEEP_COMPOSE_FILE}" ]] && warn "Compose file: ${KEEP_COMPOSE_FILE}"
      return 0
    fi
    rm -rf "${tmpdir}"
  fi
}

compose_run() {
  local project="$1"
  local file="$2"
  shift 2
  "${COMPOSE[@]}" -p "$project" -f "$file" "$@"
}

write_compose() {
  local file="$1"
  local project="$2"
  local tag="$3"
  local topology="$4" # flat|two|three
  local daemon_count="$5"
  local with_gateway="$6" # true|false

  local bind_port="7777"
  local primary_networks=()
  local daemon_networks=()

  case "$topology" in
    flat)
      primary_networks=(subnet-a)
      daemon_networks=(subnet-a)
      ;;
    two)
      primary_networks=(subnet-a subnet-b)
      daemon_networks=(subnet-a subnet-b)
      ;;
    three)
      primary_networks=(subnet-a subnet-b public)
      daemon_networks=(subnet-a subnet-b public)
      ;;
    *)
      err "unknown topology: $topology"
      return 1
      ;;
  esac

  {
    echo "services:"
    echo "  primary-node:"
    echo "    image: p2p-ddns-test-primary:${tag}"
    echo "    hostname: primary-node"
    echo "    environment:"
    echo "      - NODE_NAME=primary-node"
    echo "      - P2P_DDNS_LOG_LEVEL=debug"
    echo "      - P2P_DDNS_DOMAIN=primary-node"
    echo "      - P2P_DDNS_BIND_ADDRESS=0.0.0.0:${bind_port}"
    echo "      - XDG_RUNTIME_DIR=/tmp"
    echo "    volumes:"
    echo "      - shared-tickets:/shared"
    echo "    networks:"
    for net in "${primary_networks[@]}"; do
      echo "      ${net}: {}"
    done
    echo

    local i=1
    local gw_added="false"
    while [[ $i -le $daemon_count ]]; do
      local name
      name=$(printf "daemon-%02d" "$i")

      echo "  ${name}:"
      echo "    image: p2p-ddns-test-daemon:${tag}"
      echo "    hostname: ${name}"
      echo "    environment:"
      echo "      - NODE_NAME=${name}"
      echo "      - P2P_DDNS_LOG_LEVEL=info"
      echo "      - P2P_DDNS_DOMAIN=${name}"
      echo "      - P2P_DDNS_BIND_ADDRESS=0.0.0.0:${bind_port}"
      echo "      - TICKET_FILE=/shared/ticket.txt"
      echo "      - PRIMARY_HOST=primary-node"
      echo "      - XDG_RUNTIME_DIR=/tmp"
      echo "    volumes:"
      echo "      - shared-tickets:/shared"
      echo "    networks:"

      if [[ "$with_gateway" == "true" && "$gw_added" == "false" && "$topology" == "two" ]]; then
        # One multi-homed daemon to cover multi-address handling.
        echo "      subnet-a: {}"
        echo "      subnet-b: {}"
        gw_added="true"
      else
        # Round-robin placement across networks.
        local idx=$(( (i - 1) % ${#daemon_networks[@]} ))
        echo "      ${daemon_networks[$idx]}: {}"
      fi

      echo
      i=$((i + 1))
    done

    echo "volumes:"
    echo "  shared-tickets:"
    echo "    name: ${project}_tickets"
    echo
    echo "networks:"
    for net in "${daemon_networks[@]}"; do
      echo "  ${net}:"
      echo "    name: ${project}_${net}"
      echo "    driver: bridge"
    done
  } >"$file"
}

primary_ticket_from_logs() {
  local project="$1"
  local file="$2"
  compose_run "$project" "$file" exec -T primary-node bash -lc '
set -euo pipefail
log=/app/logs/primary.log
new=$(grep -Eo "New Ticket: [A-Za-z0-9+/]+" "$log" 2>/dev/null | tail -n 1 || true)
if [[ -n "$new" ]]; then
  echo "$new" | cut -d" " -f3
  exit 0
fi
old=$(grep -Eo "Ticket: [A-Za-z0-9+/]+" "$log" 2>/dev/null | tail -n 1 || true)
if [[ -n "$old" ]]; then
  echo "$old" | cut -d" " -f2
fi
' 2>/dev/null | tr -d '\r\n'
}

wait_for_primary_ticket() {
  local project="$1"
  local file="$2"
  local timeout="$3"

  local waited=0
  while [[ $waited -lt $timeout ]]; do
    local ticket
    ticket="$(primary_ticket_from_logs "$project" "$file" || true)"
    if [[ -n "$ticket" ]]; then
      echo "$ticket"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done

  err "primary ticket not available after ${timeout}s"
  return 1
}

sync_ticket_file() {
  local project="$1"
  local file="$2"
  local ticket="$3"
  compose_run "$project" "$file" exec -T primary-node bash -lc \
    "mkdir -p /shared && printf '%s' '$ticket' > /shared/ticket.txt"
}

primary_list() {
  local project="$1"
  local file="$2"
  local ticket="$3"
  compose_run "$project" "$file" exec -T primary-node bash -lc \
    "P2P_DDNS_TICKET='${ticket}' p2p-ddns --socket-path /tmp/p2p-ddns.sock --client list"
}

wait_for_primary_list() {
  local project="$1"
  local file="$2"
  local timeout="$3"
  shift 3
  local expected_names=("$@")

  local waited=0
  while [[ $waited -lt $timeout ]]; do
    local ticket out ok
    ticket="$(primary_ticket_from_logs "$project" "$file" || true)"
    if [[ -z "$ticket" ]]; then
      sleep 2
      waited=$((waited + 2))
      continue
    fi

    if ! out="$(primary_list "$project" "$file" "$ticket" 2>/dev/null)"; then
      sleep 2
      waited=$((waited + 2))
      continue
    fi

    ok="true"
    for name in "${expected_names[@]}"; do
      if ! grep -Fq "$name" <<<"$out"; then
        ok="false"
        break
      fi
    done

    if [[ "$ok" == "true" ]]; then
      return 0
    fi

    sleep 3
    waited=$((waited + 3))
  done

  err "primary node list did not converge after ${timeout}s"
  return 1
}

wait_for_daemon_tables() {
  local project="$1"
  local file="$2"
  local timeout="$3"
  shift 3
  local expected_names=("$@")

  local services
  services="$(compose_run "$project" "$file" config --services | tr -d '\r')"

  local check_services=()
  while read -r svc; do
    [[ -n "$svc" ]] || continue
    [[ "$svc" == daemon-* ]] || continue
    check_services+=("$svc")
  done <<<"$services"

  [[ ${#check_services[@]} -gt 0 ]] || return 0
  info "Verifying daemon stdout tables: ${check_services[*]}"

  local waited=0
  while [[ $waited -lt $timeout ]]; do
    local ok="true"
    for svc in "${check_services[@]}"; do
      local out
      out="$(compose_run "$project" "$file" logs --no-color --tail=400 "$svc" 2>/dev/null || true)"
      for name in "${expected_names[@]}"; do
        if [[ "$name" == "$svc" ]]; then
          continue
        fi
        if ! grep -Fq "$name" <<<"$out"; then
          ok="false"
          break
        fi
      done
      [[ "$ok" == "true" ]] || break
    done

    if [[ "$ok" == "true" ]]; then
      return 0
    fi

    sleep 5
    waited=$((waited + 5))
  done

  err "daemon stdout tables did not show full membership after ${timeout}s"
  return 1
}

dump_debug() {
  local project="$1"
  local file="$2"
  warn "=== docker compose ps ==="
  compose_run "$project" "$file" ps -a || true
  warn "=== docker compose logs (last 200 lines) ==="
  compose_run "$project" "$file" logs --tail=200 || true
  warn "=== per-node log files ==="
  local services
  services=$(compose_run "$project" "$file" config --services | tr -d '\r')
  while read -r svc; do
    [[ -n "$svc" ]] || continue
    if [[ "$svc" == "primary-node" || "$svc" == daemon-* ]]; then
      warn "--- $svc:/app/logs ---"
      compose_run "$project" "$file" exec -T "$svc" bash -lc 'ls -la /app/logs || true' || true
      compose_run "$project" "$file" exec -T "$svc" bash -lc 'tail -n 120 /app/logs/*.log 2>/dev/null || true' || true
    fi
  done <<<"$services"
}

run_case() {
  local case_name="$1"
  local timeout="$2"
  local tag="$3"
  local verify_all="$4"
  local keep_on_failure="$5"

  local project="p2pddns_it_${case_name//[^a-zA-Z0-9]/_}_$(date +%s)"
  local file="${tmpdir}/${project}.yml"

  local topology=""
  local daemon_count="0"
  local with_gateway="false"
  local do_partition="false"

  case "$case_name" in
    flat-2) topology="flat"; daemon_count="2" ;;
    flat-4) topology="flat"; daemon_count="4" ;;
    flat-8) topology="flat"; daemon_count="8" ;;
    two-subnet-3x3) topology="two"; daemon_count="6" ;;
    two-subnet-6x6) topology="two"; daemon_count="12" ;;
    two-subnet-gw) topology="two"; daemon_count="5"; with_gateway="true" ;;
    three-subnet-2x2x2) topology="three"; daemon_count="6" ;;
    partition-recover) topology="two"; daemon_count="6"; do_partition="true" ;;
    *)
      err "unknown case: $case_name"
      return 2
      ;;
  esac

  log "Case: $case_name (project: $project)"
  write_compose "$file" "$project" "$tag" "$topology" "$daemon_count" "$with_gateway"

  local failed="false"
  local ticket=""

  trap 'if [[ "$failed" == "true" && "$keep_on_failure" == "true" ]]; then KEEP_TMPDIR="true"; KEEP_PROJECT="'"$project"'"; KEEP_COMPOSE_FILE="'"$file"'"; warn "Keeping containers for debugging (project: '"$project"')"; warn "Compose file: '"$file"'"; else compose_run '"$project"' '"$file"' down -v --remove-orphans >/dev/null 2>&1 || true; fi' RETURN

  compose_run "$project" "$file" up -d primary-node

  ticket="$(wait_for_primary_ticket "$project" "$file" 120)" || { failed="true"; dump_debug "$project" "$file"; return 1; }
  sync_ticket_file "$project" "$file" "$ticket" || true
  info "Primary ticket acquired"

  local expected=("primary-node")
  local expected_daemons=()
  local i=1
  while [[ $i -le $daemon_count ]]; do
    local name
    name="$(printf "daemon-%02d" "$i")"
    expected+=("$name")
    expected_daemons+=("$name")
    i=$((i + 1))
  done

  i=1
  while [[ $i -le $daemon_count ]]; do
    local svc
    svc="$(printf "daemon-%02d" "$i")"
    info "Starting $svc"
    compose_run "$project" "$file" up -d "$svc"
    i=$((i + 1))
  done

  info "Waiting for primary membership to converge..."
  if ! wait_for_primary_list "$project" "$file" "$timeout" "${expected_daemons[@]}"; then
    failed="true"
    dump_debug "$project" "$file"
    return 1
  fi
  info "Converged"

  if [[ "$verify_all" == "true" ]]; then
    if ! wait_for_daemon_tables "$project" "$file" "$timeout" "${expected[@]}"; then
      failed="true"
      dump_debug "$project" "$file"
      return 1
    fi
    info "Daemon tables verified"
  fi

  if [[ "$do_partition" == "true" ]]; then
    # Sanity: while connected, primary should be able to ping a daemon on subnet-b.
    local probe="daemon-02"
    info "Partition sanity check: ping $probe from primary-node"
    compose_run "$project" "$file" exec -T primary-node bash -lc "ping -c 1 -W 1 ${probe} >/dev/null" || true

    info "Partition: disconnect primary-node from subnet-b"
    local primary_id
    primary_id="$(compose_run "$project" "$file" ps -q primary-node | tr -d '\r')"
    docker network disconnect "${project}_subnet-b" "$primary_id" || true
    sleep 10
    info "Partition sanity check: ping should fail"
    if compose_run "$project" "$file" exec -T primary-node bash -lc "ping -c 1 -W 1 ${probe} >/dev/null"; then
      warn "Expected ping to fail during partition, but it succeeded"
    fi
    info "Recover: reconnect primary-node to subnet-b"
    docker network connect "${project}_subnet-b" "$primary_id" || true

    info "Recovery sanity check: ping should succeed again"
    compose_run "$project" "$file" exec -T primary-node bash -lc "ping -c 1 -W 1 ${probe} >/dev/null" || true

    if ! wait_for_primary_list "$project" "$file" "$timeout" "${expected_daemons[@]}"; then
      failed="true"
      dump_debug "$project" "$file"
      return 1
    fi
    info "Recovered"
  fi

  return 0
}

main() {
  detect_compose
  require_docker

  local case_name=""
  local timeout="180"
  local tag="test"
  local do_build="true"
  local verify_all="false"
  local keep="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --case) case_name="${2:?missing --case value}"; shift 2 ;;
      --timeout) timeout="${2:?missing --timeout value}"; shift 2 ;;
      --tag) tag="${2:?missing --tag value}"; shift 2 ;;
      --no-build) do_build="false"; shift ;;
      --verify-all) verify_all="true"; shift ;;
      --keep) keep="true"; shift ;;
      --list) list_cases; exit 0 ;;
      --help|-h) usage; exit 0 ;;
      *) err "unknown arg: $1"; usage; exit 2 ;;
    esac
  done

  tmpdir="$(mktemp -d)"
  trap cleanup_tmpdir EXIT

  if [[ "$do_build" == "true" ]]; then
    build_images "$tag"
  fi

  local cases=()
  if [[ -n "$case_name" ]]; then
    cases=("$case_name")
  else
    cases=(flat-4 two-subnet-3x3 two-subnet-gw three-subnet-2x2x2 partition-recover)
  fi

  local failed="0"
  for c in "${cases[@]}"; do
    if ! run_case "$c" "$timeout" "$tag" "$verify_all" "$keep"; then
      failed="1"
      break
    fi
  done

  if [[ "$failed" == "0" ]]; then
    log "All cases PASSED"
  else
    err "Matrix FAILED"
    exit 1
  fi
}

main "$@"
