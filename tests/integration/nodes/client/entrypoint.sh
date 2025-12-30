#!/bin/bash

# Entry point script for client node

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] CLIENT:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] CLIENT WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] CLIENT ERROR:${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] CLIENT INFO:${NC} $1"
}

# Wait for network to be ready
wait_for_network() {
    log "Waiting for network to be ready..."

    local retries=30
    while [[ $retries -gt 0 ]]; do
        # Check for default route using either ip or route command
        if command -v ip >/dev/null 2>&1 && ip route show default >/dev/null 2>&1; then
            log "Network is ready (ip command)"
            break
        elif command -v route >/dev/null 2>&1 && route | grep -q "default"; then
            log "Network is ready (route command)"
            break
        fi
        sleep 1
        ((retries--))
    done

    if [[ $retries -eq 0 ]]; then
        warn "Network check timeout, proceeding anyway..."
        # Don't exit - just log and continue
    fi
}

# Wait for ticket file
wait_for_ticket() {
    local ticket_file="${TICKET_FILE:-/shared/ticket.txt}"
    local retries=60

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

# Wait for any daemon node to be ready
wait_for_daemons() {
    local retries=30

    log "Waiting for daemon nodes..."

    while [[ $retries -gt 0 ]]; do
        # Try to ping any daemon node
        for daemon in daemon-a1 daemon-a2 daemon-b1 daemon-b2; do
            if ping -c 1 "$daemon" >/dev/null 2>&1; then
                log "Daemon node $daemon is reachable"
                return 0
            fi
        done
        sleep 2
        ((retries--))
    done

    warn "No daemon nodes reachable, continuing anyway"
}

# Setup configuration
setup_config() {
    local node_name="${NODE_NAME:-client-node}"
    log "Setting up client node configuration for: $node_name"

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

# Monitor and display DNS information
monitor_dns() {
    local node_name="${NODE_NAME:-client-node}"
    local log_file="/app/logs/${node_name}.log"
    local monitor_interval=${DNS_MONITOR_INTERVAL:-30}

    log "Starting DNS monitoring (interval: ${monitor_interval}s)"

    while [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; do
        sleep "$monitor_interval"

        if [[ -f "$log_file" ]]; then
            # Extract DNS information from logs
            local dns_info
            dns_info=$(grep -A 10 "Address.*Name.*Last Seen" "$log_file" 2>/dev/null | tail -n +2 || true)

            if [[ -n "$dns_info" ]]; then
                info "Current DNS records:"
                echo "$dns_info" | sed 's/^/  /'
            fi
        fi
    done
}

# Validate DNS records
validate_dns() {
    local node_name="${NODE_NAME:-client-node}"
    local log_file="/app/logs/${node_name}.log"

    if [[ -f "$log_file" ]]; then
        # Check for expected DNS records
        local record_count
        record_count=$(grep -c "10\." "$log_file" 2>/dev/null || echo "0")

        info "Found $record_count DNS records"
        return 0
    fi

    return 1
}

# Setup signal handlers
setup_signal_handlers() {
    trap 'log "Received termination signal, shutting down..."; kill $PID; wait $PID; validate_dns' TERM INT
}

# Main execution
main() {
    local node_name="${NODE_NAME:-client-node}"
    log "Starting p2p-ddns client node: $node_name"

    wait_for_network
    wait_for_daemons

    setup_config "$@"
    setup_signal_handlers

    log "Starting p2p-ddns with arguments: ${ARGS[*]}"

    # Start p2p-ddns in background
    /usr/local/bin/p2p-ddns "${ARGS[@]}" > "/app/logs/${node_name}.log" 2>&1 &
    PID=$!

    # Start DNS monitoring
    monitor_dns &

    # Wait for the process
    wait $PID

    log "Client node $node_name stopped"
}

# Run main function with all arguments
main "$@"
