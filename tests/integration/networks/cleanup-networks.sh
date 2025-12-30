#!/bin/bash

# Cleanup Docker networks and containers for integration testing

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test network names
NETWORKS=("subnet-a" "subnet-b" "public")
CONTAINER_PREFIX="p2p-ddns-test"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

remove_containers() {
    log "Removing test containers..."

    local containers
    containers=$(docker ps -a --format "{{.Names}}" | grep "^${CONTAINER_PREFIX}" || true)

    if [[ -n "$containers" ]]; then
        echo "$containers" | while read -r container; do
            log "Removing container: $container"
            docker rm -f "$container" || warn "Failed to remove container $container"
        done
    else
        warn "No test containers found"
    fi
}

remove_networks() {
    log "Removing test networks..."

    for network in "${NETWORKS[@]}"; do
        if docker network ls --format "{{.Name}}" | grep -q "^${network}$"; then
            log "Removing network: $network"
            docker network rm "$network" || warn "Failed to remove network $network"
        else
            warn "Network $network not found"
        fi
    done
}

cleanup_docker_system() {
    log "Cleaning up Docker system resources..."

    # Remove dangling images
    docker image prune -f --filter "dangling=true" >/dev/null 2>&1 || true

    # Remove unused networks
    docker network prune -f >/dev/null 2>&1 || true

    # Remove unused volumes (excluding named volumes)
    docker volume prune -f >/dev/null 2>&1 || true

    log "Docker system cleanup completed"
}

show_final_status() {
    log "Cleanup completed. Current status:"
    echo

    echo "Remaining test containers:"
    docker ps -a --format "{{.Names}}" | grep "^${CONTAINER_PREFIX}" | sed 's/^/  - /' || echo "  None"
    echo

    echo "Remaining test networks:"
    docker network ls --format "{{.Name}}" | grep -E "^(subnet-a|subnet-b|public)$" | sed 's/^/  - /' || echo "  None"
    echo
}

force_cleanup() {
    log "Performing force cleanup..."

    # Stop all running containers forcefully
    docker ps --format "{{.Names}}" | grep "^${CONTAINER_PREFIX}" | while read -r container; do
        log "Force stopping container: $container"
        docker kill "$container" 2>/dev/null || true
    done

    # Remove all test containers
    remove_containers

    # Remove all test networks
    remove_networks

    # System cleanup
    cleanup_docker_system

    show_final_status
}

# Main script logic
main() {
    case "${1:-normal}" in
        normal)
            remove_containers
            remove_networks
            cleanup_docker_system
            show_final_status
            ;;
        force)
            force_cleanup
            ;;
        containers)
            remove_containers
            ;;
        networks)
            remove_networks
            ;;
        system)
            cleanup_docker_system
            ;;
        *)
            echo "Usage: $0 {normal|force|containers|networks|system}"
            echo
            echo "Commands:"
            echo "  normal     - Normal cleanup (default)"
            echo "  force      - Force cleanup (kill containers)"
            echo "  containers - Remove test containers only"
            echo "  networks   - Remove test networks only"
            echo "  system     - Cleanup Docker system resources only"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"