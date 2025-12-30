#!/bin/bash

# Quick test runner for p2p-ddns integration tests
# This script provides a simple interface to run common test scenarios

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] QUICK-TEST:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] QUICK-TEST WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] QUICK-TEST ERROR:${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] QUICK-TEST INFO:${NC} $1"
}

header() {
    echo -e "${PURPLE}=== $1 ===${NC}"
}

# Show usage
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo
    echo "Quick test runner for p2p-ddns integration tests"
    echo
    echo "Commands:"
    echo "  quick                 Run quick smoke test"
    echo "  full                  Run full test suite"
    echo "  basic                 Run basic functionality test"
    echo "  network               Run network topology test"
    echo "  fault                 Run fault recovery test"
    echo "  build                 Build Docker images"
    echo "  start                 Start test environment"
    echo "  stop                  Stop test environment"
    echo "  status                Show test environment status"
    echo "  logs                  Show container logs"
    echo "  clean                 Clean up test environment"
    echo "  help                  Show this help"
    echo
    echo "Options:"
    echo "  --timeout SECONDS     Test timeout (default: 300)"
    echo "  --debug               Enable debug logging"
    echo "  --no-build            Skip building images"
    echo "  --keep-running       Keep containers running after test"
    echo
    echo "Examples:"
    echo "  $0 quick                    # Quick smoke test"
    echo "  $0 basic --debug            # Basic test with debug logging"
    echo "  $0 full --timeout 1800      # Full test suite with 30min timeout"
    echo "  $0 start && $0 logs         # Start environment and show logs"
}

# Parse command line arguments
parse_args() {
    COMMAND=""
    TIMEOUT=300
    DEBUG=false
    BUILD_IMAGES=true
    KEEP_RUNNING=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --debug)
                DEBUG=true
                shift
                ;;
            --no-build)
                BUILD_IMAGES=false
                shift
                ;;
            --keep-running)
                KEEP_RUNNING=true
                shift
                ;;
            help|--help|-h)
                show_usage
                exit 0
                ;;
            quick|full|basic|network|fault|build|start|stop|status|logs|clean)
                if [[ -z "$COMMAND" ]]; then
                    COMMAND="$1"
                else
                    error "Multiple commands specified"
                    show_usage
                    exit 1
                fi
                shift
                ;;
            *)
                error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    if [[ -z "$COMMAND" ]]; then
        COMMAND="quick"
    fi
}

# Build Docker images
cmd_build() {
    header "Building Docker Images"

    if [[ "$BUILD_IMAGES" == true ]]; then
        "$SCRIPT_DIR/scripts/build-images-simple.sh" build --tag test
    else
        info "Skipping image build as requested"
    fi
}

# Start test environment
cmd_start() {
    header "Starting Test Environment"

    # Setup networks
    "$SCRIPT_DIR/networks/create-networks.sh" create

    # Start containers
    cd "$SCRIPT_DIR"
    docker-compose up -d

    # Wait for containers to be ready
    info "Waiting for containers to be ready..."
    sleep 30

    # Show status
    cmd_status
}

# Stop test environment
cmd_stop() {
    header "Stopping Test Environment"

    cd "$SCRIPT_DIR"
    if docker-compose ps -q | grep -q .; then
        docker-compose down
    fi

    info "Test environment stopped"
}

# Show test environment status
cmd_status() {
    header "Test Environment Status"

    cd "$SCRIPT_DIR"

    echo "Docker Networks:"
    docker network ls | grep -E "(subnet-a|subnet-b|public)" || echo "  No test networks found"
    echo

    echo "Container Status:"
    docker-compose ps
    echo

    echo "Recent Logs (last 10 lines):"
    for service in primary-node daemon-a1 daemon-b1; do
        if docker-compose ps --format "{{.Name}}" | grep -q "$service"; then
            echo "=== $service ==="
            docker-compose logs --tail=5 "$service" 2>/dev/null | tail -3 || echo "  No recent logs"
            echo
        fi
    done
}

# Show container logs
cmd_logs() {
    cd "$SCRIPT_DIR"

    if [[ "$DEBUG" == true ]]; then
        docker-compose logs -f
    else
        docker-compose logs -f --tail=50
    fi
}

# Clean up test environment
cmd_clean() {
    header "Cleaning Up Test Environment"

    # Stop containers
    cmd_stop

    # Clean up networks
    "$SCRIPT_DIR/networks/cleanup-networks.sh" normal

    # Clean up any test artifacts
    if [[ -d "$SCRIPT_DIR/logs" ]]; then
        find "$SCRIPT_DIR/logs" -name "*.log" -mtime +1 -delete 2>/dev/null || true
    fi

    if [[ -d "$SCRIPT_DIR/reports" ]]; then
        find "$SCRIPT_DIR/reports" -name "*" -mtime +7 -delete 2>/dev/null || true
    fi

    info "Test environment cleaned up"
}

# Run quick smoke test
cmd_quick() {
    header "Quick Smoke Test"

    cmd_build

    local log_level="info"
    if [[ "$DEBUG" == true ]]; then
        log_level="debug"
    fi

    # Run basic functionality test
    if "$SCRIPT_DIR/scripts/test-scenarios.sh" \
        --scenario basic-functionality \
        --timeout "$TIMEOUT" \
        --log-level "$log_level"; then

        log "Quick smoke test PASSED"

        if [[ "$KEEP_RUNNING" == false ]]; then
            cmd_clean
        fi
    else
        error "Quick smoke test FAILED"
        exit 1
    fi
}

# Run full test suite
cmd_full() {
    header "Full Test Suite"

    cmd_build

    local log_level="info"
    if [[ "$DEBUG" == true ]]; then
        log_level="debug"
    fi

    if ! "$SCRIPT_DIR/scripts/test-scenarios.sh" \
        --scenario basic-functionality \
        --timeout "$TIMEOUT" \
        --log-level "$log_level"; then
        error "Scenario FAILED: basic-functionality"
        exit 1
    fi

    if ! "$SCRIPT_DIR/scripts/test-scenarios.sh" \
        --scenario network-topology \
        --timeout "$TIMEOUT" \
        --log-level "$log_level"; then
        error "Scenario FAILED: network-topology"
        exit 1
    fi

    if ! "$SCRIPT_DIR/scripts/test-scenarios.sh" \
        --scenario fault-recovery \
        --timeout "$TIMEOUT" \
        --log-level "$log_level"; then
        error "Scenario FAILED: fault-recovery"
        exit 1
    fi

    log "Full test suite PASSED"

    if [[ "$KEEP_RUNNING" == false ]]; then
        cmd_clean
    fi
}

# Run specific test scenarios
cmd_basic() {
    header "Basic Functionality Test"

    cmd_build

    local log_level="info"
    if [[ "$DEBUG" == true ]]; then
        log_level="debug"
    fi

    if "$SCRIPT_DIR/scripts/test-scenarios.sh" \
        --scenario basic-functionality \
        --timeout "$TIMEOUT" \
        --log-level "$log_level"; then

        log "Basic functionality test PASSED"

        if [[ "$KEEP_RUNNING" == false ]]; then
            cmd_clean
        fi
    else
        error "Basic functionality test FAILED"
        exit 1
    fi
}

cmd_network() {
    header "Network Topology Test"

    cmd_build

    local log_level="info"
    if [[ "$DEBUG" == true ]]; then
        log_level="debug"
    fi

    if "$SCRIPT_DIR/scripts/test-scenarios.sh" \
        --scenario network-topology \
        --timeout "$TIMEOUT" \
        --log-level "$log_level"; then

        log "Network topology test PASSED"

        if [[ "$KEEP_RUNNING" == false ]]; then
            cmd_clean
        fi
    else
        error "Network topology test FAILED"
        exit 1
    fi
}

cmd_fault() {
    header "Fault Recovery Test"

    cmd_build

    local log_level="info"
    if [[ "$DEBUG" == true ]]; then
        log_level="debug"
    fi

    if "$SCRIPT_DIR/scripts/test-scenarios.sh" \
        --scenario fault-recovery \
        --timeout "$TIMEOUT" \
        --log-level "$log_level"; then

        log "Fault recovery test PASSED"

        if [[ "$KEEP_RUNNING" == false ]]; then
            cmd_clean
        fi
    else
        error "Fault recovery test FAILED"
        exit 1
    fi
}

# Main execution
main() {
    parse_args "$@"

    header "p2p-ddns Quick Test Runner"
    echo "Command: $COMMAND"
    echo "Timeout: ${TIMEOUT}s"
    echo "Debug: $DEBUG"
    echo

    case "$COMMAND" in
        build)
            cmd_build
            ;;
        start)
            cmd_start
            ;;
        stop)
            cmd_stop
            ;;
        status)
            cmd_status
            ;;
        logs)
            cmd_logs
            ;;
        clean)
            cmd_clean
            ;;
        quick)
            cmd_quick
            ;;
        full)
            cmd_full
            ;;
        basic)
            cmd_basic
            ;;
        network)
            cmd_network
            ;;
        fault)
            cmd_fault
            ;;
        *)
            error "Unknown command: $COMMAND"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
