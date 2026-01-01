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

    # Multi-homed test cases attach extra Docker networks after container creation.
    # Wait until we see the expected number of IPv4 addresses before starting p2p-ddns so the
    # generated ticket includes all reachable interfaces.
    local expected_ipv4="${P2P_DDNS_EXPECT_IPV4:-1}"
    local retries=60
    while [[ $retries -gt 0 ]]; do
        local ipv4_count=0
        if [[ -x /sbin/ifconfig ]]; then
            ipv4_count=$(/sbin/ifconfig 2>/dev/null | awk '$1 == "inet" && $2 !~ /^127\\./ { c++ } END { print c+0 }')
        else
            # Fallback: hostname -i may only show the primary address, but it's better than nothing.
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

    mkdir -p /app/logs
    touch /app/logs/primary.log

    # Preserve original stdout/stderr so we can dump logs without re-feeding them into tee.
    exec 3>&1 4>&2

    # Mirror all stdout/stderr into the log file while still keeping `docker logs` useful.
    exec > >(tee -a /app/logs/primary.log) 2>&1

    log "p2p-ddns --version:"
    /usr/local/bin/p2p-ddns --version || true

    # Start p2p-ddns in background
    /usr/local/bin/p2p-ddns "${ARGS[@]}" &
    PID=$!

    # Monitor the ticket and keep /shared/ticket.txt up-to-date.
    monitor_ticket &
    MONITOR_PID=$!

    # Wait for process (keep it running)
    set +e
    wait $PID 2>/dev/null
    EXIT_CODE=$?
    set -e

    kill "$MONITOR_PID" 2>/dev/null || true

    echo "----- PRIMARY: /app/logs/primary.log (tail -n 200) -----" >&3
    tail -n 200 /app/logs/primary.log 2>/dev/null >&3 || true
    echo "--------------------------------------------------------" >&3

    log "Primary node stopped (exit code: $EXIT_CODE)"
    exit "$EXIT_CODE"
}

# Run main function with all arguments
main "$@"
