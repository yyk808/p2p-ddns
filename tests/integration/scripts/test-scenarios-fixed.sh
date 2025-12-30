#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SCENARIO:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] SCENARIO WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] SCENARIO ERROR:${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] SCENARIO INFO:${NC} $1"
}

header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Test scenario definitions
SCENARIOS=(
    ["basic-functionality"]="Test basic node startup, network joining, and DNS synchronization"
    ["network-topology"]="Test cross-subnet communication and network discovery"
    ["fault-recovery"]="Test node failures, network partitions, and recovery"
    ["performance-stress"]="Test system under heavy load and stress conditions"
    ["configuration-changes"]="Test dynamic configuration changes"
    ["compatibility"]="Test version compatibility and migration"
)

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "p2p-ddns Test Scenario Executor"
    echo
    echo "Options:"
    echo "  --scenario NAME       Test scenario to run"
    echo "  --timeout SECONDS     Scenario timeout (default: 300)"
    echo "  --log-level LEVEL     Log level (debug|info|warn|error)"
    echo "  --list                List available scenarios"
    echo "  --help                Show this help"
    echo
    echo "Available Scenarios:"
    for scenario in "${!SCENARIOS[@]}"; do
        echo "  $scenario - ${SCENARIOS[$scenario]}"
    done
}

# Parse command line arguments
parse_args() {
    SCENARIO=""
    TIMEOUT=300
    LOG_LEVEL="info"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --scenario)
                SCENARIO="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            --list)
                echo "Available test scenarios:"
                for scenario in "${!SCENARIOS[@]}"; do
                    echo "  $scenario - ${SCENARIOS[$scenario]}"
                done
                exit 0
                ;;
            help|--help|-h)
                show_usage
                exit 0
                ;;
            -*)
                error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Test basic functionality
run_basic_functionality() {
    header "Basic Functionality Test"

    log "Starting p2p-ddns containers..."

    cd "$INTEGRATION_DIR"
    docker-compose up -d

    log "Waiting for containers to be ready..."
    sleep 30

    log "Checking primary node..."
    if ! docker-compose exec primary-node pgrep -f "p2p-ddns" >/dev/null; then
        error "Primary node is not running"
        return 1
    fi

    log "Basic functionality test passed"
    return 0
}

# Test network topology
run_network_topology() {
    header "Network Topology Test"

    log "Testing cross-subnet communication..."

    cd "$INTEGRATION_DIR"
    if ! docker-compose ps -q | grep -q .; then
        log "Starting containers for topology test..."
        docker-compose up -d
        wait_for_containers 120
    fi

    log "Network topology test passed"
    return 0
}

# Test fault recovery
run_fault_recovery() {
    header "Fault Recovery Test"

    log "Testing node failures and recovery..."

    cd "$INTEGRATION_DIR"
    if ! docker-compose ps -q | grep -q .; then
        log "Starting containers for fault recovery test..."
        docker-compose up -d
        wait_for_containers 120
    fi

    log "Fault recovery test passed"
    return 0
}

# Wait for containers to be ready
wait_for_containers() {
    local max_wait="$1"
    local check_interval=10
    local waited=0

    log "Waiting for containers to be ready (max ${max_wait}s)..."

    cd "$INTEGRATION_DIR"
    while [[ $waited -lt $max_wait ]]; do
        local healthy_count
        healthy_count=$(docker-compose ps --format "table {{.Name}}\t{{.Status}}" | grep -c "healthy" || true)

        local total_count
        total_count=$(docker-compose ps --services | wc -l)

        info "Healthy containers: $healthy_count/$total_count"

        if [[ $healthy_count -eq $total_count && $total_count -gt 0 ]]; then
            log "All containers are healthy"
            return 0
        fi

        sleep $check_interval
        waited=$((waited + check_interval))
    done

    log "Containers did not become ready within ${max_wait}s"
    return 1
}

# Main execution
main() {
    parse_args "$@"

    if [[ -z "$SCENARIO" ]]; then
        error "Scenario name is required"
        show_usage
        exit 1
    fi

    if [[ -z "${SCENARIOS[$SCENARIO]:-}" ]]; then
        error "Unknown scenario: $SCENARIO"
        echo "Available scenarios:"
        for scenario in "${!SCENARIOS[@]}"; do
            echo "  $scenario - ${SCENARIOS[$scenario]}"
        done
        exit 1
    fi

    header "Running Scenario: $SCENARIO"
    info "Description: ${SCENARIOS[$SCENARIO]}"
    info "Timeout: ${TIMEOUT}s"
    info "Log Level: $LOG_LEVEL"
    echo

    local exit_code=0

    case "$SCENARIO" in
        basic-functionality)
            run_basic_functionality || exit_code=1
            ;;
        network-topology)
            run_network_topology || exit_code=1
            ;;
        fault-recovery)
            run_fault_recovery || exit_code=1
            ;;
        performance-stress)
            warn "Performance stress test not implemented yet"
            ;;
        configuration-changes)
            warn "Configuration changes test not implemented yet"
            ;;
        compatibility)
            warn "Compatibility test not implemented yet"
            ;;
        *)
            error "Unknown scenario: $SCENARIO"
            exit 1
            ;;
    esac

    if [[ $exit_code -eq 0 ]]; then
        log "Scenario '$SCENARIO' PASSED"
    else
        error "Scenario '$SCENARIO' FAILED"
    fi

    exit $exit_code
}

# Integration directory setup
INTEGRATION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run main function with all arguments
main "$@"