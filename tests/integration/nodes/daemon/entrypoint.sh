#!/bin/bash

# Entry point script for daemon node

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] DAEMON:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] DAEMON WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] DAEMON ERROR:${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] DAEMON INFO:${NC} $1"
}

# Wait for network to be ready
wait_for_network() {
    log "Waiting for network to be ready..."

    # Multi-homed "gateway" test cases attach extra Docker networks after container creation.
    # Wait until we see the expected number of IPv4 addresses before starting p2p-ddns so the
    # node advertises all reachable interfaces.
    local expected_ipv4="${P2P_DDNS_EXPECT_IPV4:-1}"
    local retries=60
    while [[ $retries -gt 0 ]]; do
        local ipv4_count=0
        if [[ -x /sbin/ifconfig ]]; then
            ipv4_count=$(/sbin/ifconfig 2>/dev/null | awk '$1 == "inet" && $2 !~ /^127\\./ { c++ } END { print c+0 }')
        else
            local ips
            ips=$(hostname -i 2>/dev/null || true)
            for ip in $ips; do
                if [[ "$ip" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$ && "$ip" != 127.* ]]; then
                    ((ipv4_count++))
                fi
            done
        fi
        if [[ $ipv4_count -ge $expected_ipv4 ]]; then
            log "Network is ready (ipv4 addresses: ${ipv4_count}/${expected_ipv4})"
            return 0
        fi
        sleep 1
        ((retries--))
    done

    if [[ $retries -eq 0 ]]; then
        warn "Network check timeout (ipv4 addresses < ${expected_ipv4}), proceeding anyway..."
        # Don't exit - just log and continue
    fi
}

# Wait for ticket file
wait_for_ticket() {
    local ticket_file="${TICKET_FILE:-/shared/ticket.txt}"
    local retries=60
    local timeout=${TICKET_WAIT_TIMEOUT:-60}

    log "Waiting for ticket file: $ticket_file" >&2

    while [[ $retries -gt 0 ]]; do
        if [[ -f "$ticket_file" && -s "$ticket_file" ]]; then
            local ticket
            ticket=$(cat "$ticket_file" | tr -d '\n')
            if [[ -n "$ticket" ]]; then
                log "Ticket found: $ticket" >&2
                echo "$ticket"
                return 0
            fi
        fi
        sleep 1
        ((retries--))
    done

    error "Ticket file not found or empty after timeout"
    return 1
}

# Wait for primary node to be ready
wait_for_primary() {
    local primary_host="${PRIMARY_HOST:-primary-node}"
    local retries=30

    log "Waiting for primary node: $primary_host"

    while [[ $retries -gt 0 ]]; do
        if ping -c 1 "$primary_host" >/dev/null 2>&1; then
            log "Primary node is reachable"
            return 0
        fi
        sleep 2
        ((retries--))
    done

    warn "Primary node not reachable, continuing anyway"
}

# Setup configuration
setup_config() {
    local node_name="${NODE_NAME:-daemon-node}"
    log "Setting up daemon node configuration for: $node_name"

    # Ensure data directory exists
    mkdir -p /app/data
    mkdir -p /app/logs

    ARGS=("$@")

    # Set log level from environment
    if [[ -n "${P2P_DDNS_LOG_LEVEL:-}" ]]; then
        log "Setting log level to: $P2P_DDNS_LOG_LEVEL"
        ARGS+=("--log" "$P2P_DDNS_LOG_LEVEL")
    fi

    # Set custom domain if provided
    if [[ -n "${P2P_DDNS_DOMAIN:-}" ]]; then
        log "Setting domain to: $P2P_DDNS_DOMAIN"
        ARGS+=("--domain" "$P2P_DDNS_DOMAIN")
    fi

    # Set custom bind address if provided
    if [[ -n "${P2P_DDNS_BIND_ADDRESS:-}" ]]; then
        log "Setting bind address to: $P2P_DDNS_BIND_ADDRESS"
        ARGS+=("--bind" "$P2P_DDNS_BIND_ADDRESS")
    fi

    # Storage directory (this project's CLI expects a directory)
    ARGS+=("--config" "/app/data")

    # Add ticket if available
    if [[ -n "${P2P_DDNS_TICKET:-}" ]]; then
        log "Using provided ticket"
        ARGS+=("--ticket" "$P2P_DDNS_TICKET")
    else
        # Try to get ticket from file
        local ticket
        ticket=$(wait_for_ticket)
        if [[ -n "$ticket" ]]; then
            ARGS+=("--ticket" "$ticket")
        fi
    fi
}

# Health check function
health_check() {
    local node_name="${NODE_NAME:-daemon-node}"
    local log_file="/app/logs/${node_name}.log"

    if [[ -f "$log_file" ]]; then
        # Check for recent activity
        local recent_logs
        recent_logs=$(tail -n 10 "$log_file" 2>/dev/null || true)

        if echo "$recent_logs" | grep -q "ERROR"; then
            return 1
        fi

        # Check if process is running
        if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
            return 0
        fi
    fi

    return 1
}

# Setup signal handlers
setup_signal_handlers() {
    trap 'log "Received termination signal, shutting down..."; kill ${TAIL_PID:-} 2>/dev/null || true; kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true' TERM INT
}

# Monitor node health
monitor_health() {
    local check_interval=${HEALTH_CHECK_INTERVAL:-30}

    while [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; do
        sleep "$check_interval"

        if ! health_check; then
            warn "Health check failed, but continuing..."
        fi
    done
}

# Main execution
main() {
    local node_name="${NODE_NAME:-daemon-node}"
    log "Starting p2p-ddns daemon node: $node_name"

    wait_for_network
    wait_for_primary

    setup_config "$@"
    setup_signal_handlers

    log "Starting p2p-ddns with arguments: ${ARGS[*]}"

    local log_file="/app/logs/${node_name}.log"
    touch "$log_file"

    # Preserve original stdout/stderr so we can dump logs without re-feeding them into tee.
    exec 3>&1 4>&2

    # Mirror all stdout/stderr into the per-node log file while still keeping `docker logs` useful.
    exec > >(tee -a "$log_file") 2>&1

    log "p2p-ddns --version:"
    /usr/local/bin/p2p-ddns --version || true

    # Start p2p-ddns in background
    /usr/local/bin/p2p-ddns "${ARGS[@]}" &
    PID=$!

    # Start health monitoring
    monitor_health &

    # Wait for the process
    set +e
    wait $PID
    EXIT_CODE=$?
    set -e

    echo "----- DAEMON: ${log_file} (tail -n 200) -----" >&3
    tail -n 200 "$log_file" 2>/dev/null >&3 || true
    echo "--------------------------------------------" >&3

    log "Daemon node $node_name stopped (exit code: $EXIT_CODE)"
    exit "$EXIT_CODE"
}

# Run main function with all arguments
main "$@"
