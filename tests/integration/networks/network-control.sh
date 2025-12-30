#!/bin/bash

# Network control script for integration testing
# Allows manipulating network connectivity between containers for testing network partitions

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Container prefix
CONTAINER_PREFIX="p2p-ddns-test"

has_linux_net_tools() {
    command -v ip >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1
}

require_linux_net_tools_or_skip() {
    if ! has_linux_net_tools; then
        warn "Linux network tools (ip/iptables) not available; skipping network-control action"
        return 1
    fi
    return 0
}

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

container_exists() {
    local container_name=$1
    docker ps -a --format "{{.Names}}" | grep -q "^${container_name}$"
}

get_container_pid() {
    local container_name=$1
    if container_exists "$container_name"; then
        docker inspect "$container_name" --format "{{.State.Pid}}"
    else
        echo ""
    fi
}

isolate_container() {
    local container_name=$1
    local container_pid

    if ! require_linux_net_tools_or_skip; then
        return 0
    fi

    container_pid=$(get_container_pid "$container_name")
    if [[ -z "$container_pid" ]]; then
        error "Container $container_name not found or not running"
    fi

    log "Isolating container: $container_name (PID: $container_pid)"

    # Create network namespace isolation
    if ! sudo ip netns list | grep -q "test-${container_name}"; then
        sudo mkdir -p /var/run/netns
        sudo ln -sf "/proc/$container_pid/ns/net" "/var/run/netns/test-${container_name}" || error "Failed to create network namespace for $container_name"
    fi

    # Add firewall rules to block all traffic except localhost
    sudo iptables -I DOCKER-USER -s 0.0.0.0/0 -d 0.0.0.0/0 -m comment --comment "isolate-${container_name}" -j DROP || warn "Failed to add isolation rules for $container_name"

    log "Container $container_name isolated successfully"
}

restore_container() {
    local container_name=$1
    local container_pid

    if ! require_linux_net_tools_or_skip; then
        return 0
    fi

    container_pid=$(get_container_pid "$container_name")
    if [[ -z "$container_pid" ]]; then
        warn "Container $container_name not found or not running"
        return 0
    fi

    log "Restoring network connectivity for: $container_name"

    # Remove network namespace link
    if sudo ip netns list | grep -q "test-${container_name}"; then
        sudo rm -f "/var/run/netns/test-${container_name}" || warn "Failed to remove network namespace for $container_name"
    fi

    # Remove firewall rules
    sudo iptables -D DOCKER-USER -m comment --comment "isolate-${container_name}" -j DROP 2>/dev/null || warn "Failed to remove isolation rules for $container_name"

    log "Network connectivity restored for $container_name"
}

isolate_network() {
    local network_name=$1
    log "Isolating network: $network_name"

    local containers
    containers=$(docker ps --format "{{.Names}}" | grep "^${CONTAINER_PREFIX}" | grep "$network_name" || true)

    if [[ -z "$containers" ]]; then
        warn "No containers found in network $network_name"
        return 0
    fi

    echo "$containers" | while read -r container; do
        isolate_container "$container"
    done

    log "Network $network_name isolated successfully"
}

restore_network() {
    local network_name=$1
    log "Restoring network: $network_name"

    local containers
    containers=$(docker ps --format "{{.Names}}" | grep "^${CONTAINER_PREFIX}" | grep "$network_name" || true)

    if [[ -z "$containers" ]]; then
        warn "No containers found in network $network_name"
        return 0
    fi

    echo "$containers" | while read -r container; do
        restore_container "$container"
    done

    log "Network $network_name restored successfully"
}

block_container_connection() {
    local source_container=$1
    local target_container=$2

    if ! require_linux_net_tools_or_skip; then
        return 0
    fi

    if ! container_exists "$source_container" || ! container_exists "$target_container"; then
        error "One or both containers not found"
    fi

    log "Blocking connection from $source_container to $target_container"

    local source_ip
    local target_ip

    source_ip=$(docker inspect "$source_container" --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
    target_ip=$(docker inspect "$target_container" --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")

    if [[ -z "$source_ip" || -z "$target_ip" ]]; then
        error "Failed to get IP addresses for containers"
    fi

    # Add iptables rule to block traffic
    sudo iptables -I DOCKER-USER -s "$source_ip" -d "$target_ip" -j DROP -m comment --comment "block-${source_container}-to-${target_container}" || warn "Failed to add block rule"

    log "Connection blocked: $source_container ($source_ip) -> $target_container ($target_ip)"
}

restore_container_connection() {
    local source_container=$1
    local target_container=$2

    if ! require_linux_net_tools_or_skip; then
        return 0
    fi

    log "Restoring connection from $source_container to $target_container"

    # Remove iptables rule
    sudo iptables -D DOCKER-USER -m comment --comment "block-${source_container}-to-${target_container}" -j DROP 2>/dev/null || warn "Failed to remove block rule"

    log "Connection restored: $source_container -> $target_container"
}

show_network_status() {
    info "Network control status:"
    echo

    # Show isolated containers
    local isolated_namespaces
    if has_linux_net_tools; then
        isolated_namespaces=$(sudo ip netns list | grep "test-" | sed 's/test-//' || true)
    else
        isolated_namespaces=""
    fi

    if [[ -n "$isolated_namespaces" ]]; then
        echo "Isolated containers:"
        echo "$isolated_namespaces" | sed 's/^/  - /'
        echo
    else
        echo "No isolated containers"
        echo
    fi

    # Show firewall rules
    local firewall_rules
    if has_linux_net_tools; then
        firewall_rules=$(sudo iptables -L DOCKER-USER --line-numbers | grep -E "(isolate-|block-)" || true)
    else
        firewall_rules=""
    fi

    if [[ -n "$firewall_rules" ]]; then
        echo "Active firewall rules:"
        echo "$firewall_rules" | sed 's/^/  /'
        echo
    else
        echo "No custom firewall rules"
        echo
    fi

    # Show container connectivity
    echo "Container status:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(NAMES|${CONTAINER_PREFIX})" || echo "  No test containers running"
}

cleanup_all() {
    log "Cleaning up all network control rules..."

    if ! require_linux_net_tools_or_skip; then
        log "Network control cleanup skipped"
        return 0
    fi

    # Remove all network namespaces
    sudo ip netns list | grep "test-" | while read -r ns; do
        sudo ip netns delete "$ns" || warn "Failed to remove namespace $ns"
    done

    # Remove all custom iptables rules
    local rule_numbers
    rule_numbers=$(sudo iptables -L DOCKER-USER --line-numbers | grep -E "(isolate-|block-)" | awk '{print $1}' | sort -nr)

    if [[ -n "$rule_numbers" ]]; then
        echo "$rule_numbers" | while read -r rule_num; do
            sudo iptables -D DOCKER-USER "$rule_num" || warn "Failed to remove rule $rule_num"
        done
    fi

    log "Network control cleanup completed"
}

# Main script logic
main() {
    # Check if running with appropriate privileges
    if [[ $EUID -ne 0 ]]; then
        warn "Some operations require sudo privileges"
    fi

    case "${1:-status}" in
        isolate-container)
            if [[ $# -ne 2 ]]; then
                error "Usage: $0 isolate-container <container-name>"
            fi
            isolate_container "$2"
            ;;
        restore-container)
            if [[ $# -ne 2 ]]; then
                error "Usage: $0 restore-container <container-name>"
            fi
            restore_container "$2"
            ;;
        isolate-network)
            if [[ $# -ne 2 ]]; then
                error "Usage: $0 isolate-network <network-name>"
            fi
            isolate_network "$2"
            ;;
        restore-network)
            if [[ $# -ne 2 ]]; then
                error "Usage: $0 restore-network <network-name>"
            fi
            restore_network "$2"
            ;;
        block-connection)
            if [[ $# -ne 3 ]]; then
                error "Usage: $0 block-connection <source-container> <target-container>"
            fi
            block_container_connection "$2" "$3"
            ;;
        restore-connection)
            if [[ $# -ne 3 ]]; then
                error "Usage: $0 restore-connection <source-container> <target-container>"
            fi
            restore_container_connection "$2" "$3"
            ;;
        status)
            show_network_status
            ;;
        cleanup)
            cleanup_all
            ;;
        *)
            echo "Usage: $0 {isolate-container|restore-container|isolate-network|restore-network|block-connection|restore-connection|status|cleanup}"
            echo
            echo "Commands:"
            echo "  isolate-container <name>  - Isolate a single container"
            echo "  restore-container <name>  - Restore container connectivity"
            echo "  isolate-network <name>    - Isolate all containers in a network"
            echo "  restore-network <name>    - Restore network connectivity"
            echo "  block-connection <src> <dst> - Block specific connection"
            echo "  restore-connection <src> <dst> - Restore specific connection"
            echo "  status                   - Show current network status"
            echo "  cleanup                  - Clean up all network control rules"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
