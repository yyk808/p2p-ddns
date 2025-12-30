#!/bin/bash

# Health check script for p2p-ddns containers

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] HEALTH:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] HEALTH WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] HEALTH ERROR:${NC} $1" >&2
}

# Get container type from environment or labels
get_container_type() {
    # Try environment variable first
    if [[ -n "${P2P_DDNS_MODE:-}" ]]; then
        echo "$P2P_DDNS_MODE"
        return 0
    fi

    # Try to detect from container name
    local container_name
    container_name=$(hostname 2>/dev/null || echo "unknown")

    if [[ "$container_name" =~ primary ]]; then
        echo "primary"
    elif [[ "$container_name" =~ daemon ]]; then
        echo "daemon"
    elif [[ "$container_name" =~ client ]]; then
        echo "client"
    else
        echo "unknown"
    fi
}

# Check if process is running
check_process() {
    local container_type
    container_type=$(get_container_type)

    # Check if p2p-ddns process is running
    if pgrep -f "p2p-ddns" >/dev/null 2>&1; then
        log "p2p-ddns process is running"
        return 0
    else
        error "p2p-ddns process not found"
        return 1
    fi
}

# Check log files for errors
check_logs() {
    local container_type
    container_type=$(get_container_type)
    local log_dir="/app/logs"

    if [[ ! -d "$log_dir" ]]; then
        warn "Log directory not found: $log_dir"
        return 0
    fi

    # Find log files
    local log_files
    case "$container_type" in
        primary)
            log_files=$(find "$log_dir" -name "primary.log" 2>/dev/null || true)
            ;;
        daemon)
            log_files=$(find "$log_dir" -name "daemon*.log" 2>/dev/null || true)
            ;;
        client)
            log_files=$(find "$log_dir" -name "client*.log" 2>/dev/null || true)
            ;;
        *)
            log_files=$(find "$log_dir" -name "*.log" 2>/dev/null || true)
            ;;
    esac

    local has_errors=0

    for log_file in $log_files; do
        if [[ -f "$log_file" ]]; then
            # Check for fatal conditions (last 50 lines).
            # Normal "ERROR" logs can be expected in transient network conditions and should not
            # flip container health to "unhealthy" during integration tests.
            local recent_errors
            recent_errors=$(tail -n 50 "$log_file" 2>/dev/null | grep -i "fatal\\|panic" || true)

            if [[ -n "$recent_errors" ]]; then
                error "Recent errors found in $log_file:"
                echo "$recent_errors" | sed 's/^/  /'
                has_errors=1
            fi

            # Check if log file is being updated (modified in last 2 minutes)
            local log_age
            log_age=$(find "$log_file" -mmin -2 2>/dev/null || true)

            if [[ -z "$log_age" ]]; then
                warn "Log file $log_file hasn't been updated recently"
            fi
        fi
    done

    return $has_errors
}

# Check network connectivity
check_network() {
    # In isolated-topology tests, containers may be intentionally placed on separate networks.
    # Health checks must not require cross-network connectivity; integration tests assert that separately.

    if command -v ip >/dev/null 2>&1; then
        if ip route show default >/dev/null 2>&1; then
            log "Network routing is configured (ip)"
            return 0
        fi
    fi

    if command -v route >/dev/null 2>&1; then
        if route | grep -q "default"; then
            log "Network routing is configured (route)"
            return 0
        fi
    fi

    warn "No default route found (may be expected in some test environments)"
    return 0
}

# Check ticket generation (for primary node)
check_ticket() {
    local container_type
    container_type=$(get_container_type)

    if [[ "$container_type" == "primary" ]]; then
        local ticket_file="/app/ticket.txt"

        if [[ -f "$ticket_file" && -s "$ticket_file" ]]; then
            local ticket
            ticket=$(cat "$ticket_file" 2>/dev/null | tr -d '\n' || true)

            if [[ -n "$ticket" ]]; then
                log "Ticket file exists and contains data"
                return 0
            else
                warn "Ticket file exists but is empty"
                return 1
            fi
        else
            warn "Ticket file not found or empty"
            return 1
        fi
    fi

    return 0
}

# Check DNS records (for all nodes)
check_dns_records() {
    local container_type
    container_type=$(get_container_type)
    local log_dir="/app/logs"

    if [[ ! -d "$log_dir" ]]; then
        return 0
    fi

    # Find the main log file
    local main_log
    case "$container_type" in
        primary)
            main_log="$log_dir/primary.log"
            ;;
        daemon)
            main_log=$(find "$log_dir" -name "daemon*.log" 2>/dev/null | head -n 1)
            ;;
        client)
            main_log=$(find "$log_dir" -name "client*.log" 2>/dev/null | head -n 1)
            ;;
        *)
            main_log=$(find "$log_dir" -name "*.log" 2>/dev/null | head -n 1)
            ;;
    esac

    if [[ -f "$main_log" ]]; then
        # Check for DNS table output
        local dns_records
        dns_records=$(grep -A 20 "Address.*Name.*Last Seen" "$main_log" 2>/dev/null | tail -n +2 || true)

        if [[ -n "$dns_records" ]]; then
            local record_count
            record_count=$(echo "$dns_records" | grep -c "10\." || echo "0")
            log "Found $record_count DNS records"
            return 0
        else
            warn "No DNS records found in logs"
            return 1
        fi
    fi

    return 0
}

# Main health check
main() {
    local overall_status=0

    log "Starting health check for $(get_container_type) node"

    # Check process
    if ! check_process; then
        overall_status=1
    fi

    # Check logs
    if ! check_logs; then
        overall_status=1
    fi

    # Check network
    if ! check_network; then
        overall_status=1
    fi

    # Check ticket (for primary)
    if ! check_ticket; then
        overall_status=1
    fi

    # Check DNS records
    if ! check_dns_records; then
        # DNS records not being present is not a critical error for all nodes
        # so we don't set overall_status here
        true
    fi

    if [[ $overall_status -eq 0 ]]; then
        log "Health check passed"
    else
        error "Health check failed"
    fi

    return $overall_status
}

# Run main function
main "$@"
