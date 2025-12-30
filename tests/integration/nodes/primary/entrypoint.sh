#!/bin/bash

# Entry point script for primary node

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] PRIMARY:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] PRIMARY WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] PRIMARY ERROR:${NC} $1" >&2
}

# Wait for network to be ready
wait_for_network() {
    log "Waiting for network to be ready..."

    # Wait for network interface to be up
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

# Setup configuration
setup_config() {
    log "Setting up primary node configuration..."
    
    # Ensure data directory exists
    mkdir -p /app/data
    
    # Build command line arguments
    ARGS=("--daemon" "--primary" "--config" "/app/data")
    
    # Set log level from environment if provided
    if [[ -n "${P2P_DDNS_LOG_LEVEL:-}" ]]; then
        log "Setting log level to: $P2P_DDNS_LOG_LEVEL"
        ARGS+=("--log" "$P2P_DDNS_LOG_LEVEL")
    else
        # Integration tests rely on reading the ticket from logs; keep this verbose by default.
        ARGS+=("--log" "debug")
    fi
    
    # Set custom domain if provided
    if [[ -n "${P2P_DDNS_DOMAIN:-}" ]]; then
        log "Setting domain to: $P2P_DDNS_DOMAIN"
        ARGS+=("--domain" "$P2P_DDNS_DOMAIN")
    else
        ARGS+=("--domain" "primary-node")
    fi
    
    # Set custom bind address if provided
    if [[ -n "${P2P_DDNS_BIND_ADDRESS:-}" ]]; then
        log "Setting bind address to: $P2P_DDNS_BIND_ADDRESS"
        ARGS+=("--bind" "$P2P_DDNS_BIND_ADDRESS")
    fi
}

# Save ticket for other nodes
monitor_ticket() {
    log "Monitoring ticket updates..."

    local log_file="/app/logs/primary.log"
    local ticket_file="/app/ticket.txt"
    local shared_ticket_file="/shared/ticket.txt"
    local last_ticket=""

    while true; do
        local ticket=""

        if [[ -f "$log_file" ]]; then
            ticket=$(grep -Eo "New Ticket: [a-zA-Z0-9+/]+" "$log_file" 2>/dev/null | tail -1 | cut -d' ' -f3 || true)
            if [[ -z "$ticket" ]]; then
                ticket=$(grep -Eo "Ticket: [a-zA-Z0-9+/]+" "$log_file" 2>/dev/null | tail -1 | cut -d' ' -f2 || true)
            fi
        fi

        if [[ -n "$ticket" && "$ticket" != "$last_ticket" ]]; then
            printf '%s' "$ticket" > "$ticket_file"
            if [[ -d /shared ]]; then
                printf '%s' "$ticket" > "$shared_ticket_file"
            fi
            last_ticket="$ticket"
            log "Ticket updated: $ticket"
        fi

        sleep 1
    done
}

# Setup signal handlers
setup_signal_handlers() {
    # Handle graceful shutdown
    trap 'log "Received termination signal, shutting down..."; kill ${MONITOR_PID:-} 2>/dev/null || true; kill ${TAIL_PID:-} 2>/dev/null || true; kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true' TERM INT
}

# Main execution
main() {
    log "Starting p2p-ddns primary node..."

    wait_for_network
    setup_config
    setup_signal_handlers

    log "Starting p2p-ddns with arguments: ${ARGS[*]}"

    # Start p2p-ddns in background
    mkdir -p /app/logs
    /usr/local/bin/p2p-ddns "${ARGS[@]}" > /app/logs/primary.log 2>&1 &
    PID=$!

    # Stream logs to stdout for easier debugging from `docker logs`.
    tail -n 0 -F /app/logs/primary.log &
    TAIL_PID=$!

    # Monitor the ticket and keep /shared/ticket.txt up-to-date.
    monitor_ticket &
    MONITOR_PID=$!

    # Wait for process (keep it running)
    wait $PID 2>/dev/null

    kill "$TAIL_PID" 2>/dev/null || true
    kill "$MONITOR_PID" 2>/dev/null || true

    log "Primary node stopped (exit code: $?)"
}

# Run main function with all arguments
main "$@"
