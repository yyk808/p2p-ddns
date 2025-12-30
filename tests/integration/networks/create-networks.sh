#!/bin/bash

# Create Docker networks for integration testing
# This script simulates a multi-subnet network environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Network configurations - simple arrays with name:subnet:gateway format
NETWORK_CONFIGS=(
    "subnet-a:10.0.1.0/24:10.0.1.1"
    "subnet-b:10.0.2.0/24:10.0.2.1"
    "public:10.0.0.0/24:10.0.0.1"
)

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
    exit 1
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed or not in PATH"
    fi

    if ! docker info &> /dev/null; then
        error "Docker daemon is not running"
    fi

    log "Docker check passed"
}

network_exists() {
    local network_name=$1
    docker network ls --format "{{.Name}}" | grep -q "^${network_name}$"
}

create_network() {
    local network_name=$1
    local subnet=$2
    local gateway=$3

    if network_exists "$network_name"; then
        warn "Network $network_name already exists, skipping creation"
        return 0
    fi

    log "Creating network: $network_name (subnet: $subnet, gateway: $gateway)"

    docker network create \
        --driver=bridge \
        --subnet="$subnet" \
        --gateway="$gateway" \
        --opt com.docker.network.bridge.enable_ip_masquerade=true \
        --opt com.docker.network.bridge.enable_icc=true \
        --opt com.docker.network.driver.mtu=1500 \
        "$network_name" || error "Failed to create network $network_name"

    log "Successfully created network: $network_name"
}

verify_network() {
    local network_name=$1
    local expected_subnet=$2

    log "Verifying network: $network_name"

    local network_info
    # Get the first subnet only (usually IPv4)
    network_info=$(docker network inspect "$network_name" --format '{{(index .IPAM.Config 0).Subnet}}')

    if [[ -z "$network_info" ]]; then
        error "Network $network_name has no IPv4 subnet. Got: $(docker network inspect "$network_name" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}')"
    fi

    if [[ "$network_info" != "$expected_subnet" ]]; then
        error "Network $network_name has incorrect subnet. Expected: $expected_subnet, Got: $network_info"
    fi

    log "Network $network_name verified successfully"
}

create_test_networks() {
    log "Starting creation of test networks..."

    for config in "${NETWORK_CONFIGS[@]}"; do
        # Split config into name, subnet, gateway
        IFS=':' read -r network_name subnet gateway <<< "$config"

        create_network "$network_name" "$subnet" "$gateway"
        verify_network "$network_name" "$subnet"
    done

    log "All test networks created successfully"
}

show_network_info() {
    log "Current Docker networks:"
    echo
    docker network ls | grep -E "(subnet-a|subnet-b|public)" || warn "No test networks found"
    echo

    for config in "${NETWORK_CONFIGS[@]}"; do
        # Split config into name, subnet, gateway
        IFS=':' read -r network_name subnet gateway <<< "$config"

        if network_exists "$network_name"; then
            log "Details for $network_name:"
            docker network inspect "$network_name" --format '
Network: {{.Name}}
Subnet: {{range .IPAM.Config}}{{.Subnet}}{{end}}
Gateway: {{range .IPAM.Config}}{{.Gateway}}{{end}}
Containers: {{len .Containers}}
---
'
        fi
    done
}

cleanup_networks() {
    log "Cleaning up test networks..."

    for config in "${NETWORK_CONFIGS[@]}"; do
        # Split config into name, subnet, gateway
        IFS=':' read -r network_name subnet gateway <<< "$config"

        if network_exists "$network_name"; then
            log "Removing network: $network_name"
            docker network rm "$network_name" || warn "Failed to remove network $network_name"
        else
            warn "Network $network_name does not exist, skipping cleanup"
        fi
    done

    log "Network cleanup completed"
}

# Main script logic
main() {
    case "${1:-create}" in
        create)
            check_docker
            create_test_networks
            show_network_info
            ;;
        cleanup)
            cleanup_networks
            ;;
        verify)
            check_docker
            for config in "${NETWORK_CONFIGS[@]}"; do
                # Split config into name, subnet, gateway
                IFS=':' read -r network_name subnet gateway <<< "$config"

                if network_exists "$network_name"; then
                    verify_network "$network_name" "$subnet"
                else
                    warn "Network $network_name does not exist"
                fi
            done
            ;;
        info)
            show_network_info
            ;;
        *)
            echo "Usage: $0 {create|cleanup|verify|info}"
            echo
            echo "Commands:"
            echo "  create   - Create test networks (default)"
            echo "  cleanup  - Remove test networks"
            echo "  verify   - Verify network configurations"
            echo "  info     - Show network information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"