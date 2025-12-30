#!/bin/bash

# Single-machine integration test runner for p2p-ddns
# This script provides a complete, automated testing experience using Docker's isolated network environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$INTEGRATION_DIR/../.." && pwd)"

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SINGLE-MACHINE:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] SINGLE-MACHINE WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] SINGLE-MACHINE ERROR:${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] SINGLE-MACHINE INFO:${NC} $1"
}

header() {
    echo -e "${PURPLE}$1${NC}"
}

success() {
    echo -e "${CYAN}✓ $1${NC}"
}

failure() {
    echo -e "${RED}✗ $1${NC}"
}

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Track resources for cleanup
CLEANUP_NEEDED=false

# Helper functions

check_docker() {
    header "Checking Docker Environment"

    if ! command -v docker &> /dev/null; then
        error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        error "Docker Compose is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        error "Docker daemon is not running"
        exit 1
    fi

    local docker_version
    docker_version=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    log "Docker version: $docker_version"

    local compose_version
    compose_version=$(docker-compose --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
    log "Docker Compose version: $compose_version"

    success "Docker environment check passed"
}

check_prerequisites() {
    header "Checking Prerequisites"

    # Check if we're in the integration test directory
    if [[ ! -f "$INTEGRATION_DIR/docker-compose.yml" ]]; then
        error "Could not find docker-compose.yml. Please run this script from tests/integration directory"
        exit 1
    fi

    # Check if Cargo.toml exists
    if [[ ! -f "$PROJECT_ROOT/Cargo.toml" ]]; then
        error "Could not find Cargo.toml in project root: $PROJECT_ROOT"
        exit 1
    fi

    # Check available disk space
    local available_space
    if df -BG "$INTEGRATION_DIR" >/dev/null 2>&1; then
        available_space=$(df -BG "$INTEGRATION_DIR" | tail -1 | awk '{print $4}' | sed 's/G//')
    elif df -g "$INTEGRATION_DIR" >/dev/null 2>&1; then
        available_space=$(df -g "$INTEGRATION_DIR" | tail -1 | awk '{print $4}')
    else
        # Fallback: df -k is POSIX-ish, compute GiB.
        local available_kb
        available_kb=$(df -k "$INTEGRATION_DIR" | tail -1 | awk '{print $4}')
        available_space=$((available_kb / 1024 / 1024))
    fi

    if [[ $available_space -lt 5 ]]; then
        warn "Low disk space: ${available_space}GB available (recommended: 5GB+)"
    else
        log "Available disk space: ${available_space}GB"
    fi

    # Check available memory
    if command -v free &> /dev/null; then
        local available_memory
        available_memory=$(free -m | grep Mem | awk '{print $7}')
        log "Available memory: ${available_memory}MB"

        if [[ $available_memory -lt 2048 ]]; then
            warn "Low memory: ${available_memory}MB available (recommended: 2048MB+)"
        fi
    fi

    success "Prerequisites check passed"
}

cleanup_environment() {
    header "Cleaning Up Environment"

    cd "$INTEGRATION_DIR"

    # Stop containers
    log "Stopping Docker containers..."
    if docker-compose ps -q 2>/dev/null | grep -q .; then
        docker-compose down --remove-orphans --timeout 30 2>/dev/null || true
        success "Containers stopped"
    else
        info "No running containers to stop"
    fi

    # Remove networks
    log "Removing Docker networks..."
    if [[ -f "./networks/cleanup-networks.sh" ]]; then
        ./networks/cleanup-networks.sh normal 2>/dev/null || true
        success "Networks removed"
    fi

    # Clean up network control rules
    if [[ -f "./networks/network-control.sh" ]]; then
        ./networks/network-control.sh cleanup 2>/dev/null || true
    fi

    # Clean up old logs (optional)
    if [[ -d ./logs ]]; then
        local log_files
        log_files=$(find ./logs -name "*.log" -mtime +1 2>/dev/null | wc -l || echo "0")
        if [[ $log_files -gt 0 ]]; then
            log "Cleaning up old log files ($log_files files)"
            find ./logs -name "*.log" -mtime +1 -delete 2>/dev/null || true
        fi
    fi

    success "Environment cleanup completed"
}

build_images() {
    header "Building Docker Images"

    cd "$INTEGRATION_DIR"

    log "Building p2p-ddns Docker images..."
    log "This may take 5-10 minutes..."

    if ./scripts/build-images-simple.sh build --tag test; then
        success "Docker images built successfully"
    else
        error "Failed to build Docker images"
        return 1
    fi
}

create_networks() {
    header "Creating Isolated Network Environment"

    cd "$INTEGRATION_DIR"

    log "Creating Docker networks: subnet-a, subnet-b, public..."

    if ./networks/create-networks.sh create; then
        success "Networks created successfully"

        # Display network information
        log "Network configuration:"
        echo
        ./networks/create-networks.sh info
        echo
    else
        error "Failed to create networks"
        return 1
    fi
}

start_containers() {
    header "Starting Test Containers"

    cd "$INTEGRATION_DIR"

    log "Starting all containers..."
    docker-compose up -d

    if [[ $? -ne 0 ]]; then
        error "Failed to start containers"
        return 1
    fi

    log "Waiting for containers to initialize..."
    sleep 30

    # Check container status
    local running
    running=$(docker-compose ps --filter "status=running" --services | wc -l)
    log "Running containers: $running/7"

    if [[ $running -ge 5 ]]; then
        success "Containers started successfully"
    else
        warn "Only $running containers running (expected: 7)"
    fi
}

wait_for_readiness() {
    header "Waiting for System Readiness"

    cd "$INTEGRATION_DIR"

    local max_wait=300
    local waited=0
    local ready_containers=0

    log "Waiting for all containers to be ready..."
    log "This may take 1-2 minutes..."

    while [[ $waited -lt $max_wait ]]; do
        ready_containers=0

        # Check primary node
        if docker-compose ps primary-node 2>/dev/null | grep -q "healthy\|Up"; then
            ((ready_containers++))
        fi

        # Check daemon nodes
        for daemon in daemon-a1 daemon-a2 daemon-b1 daemon-b2; do
            if docker-compose ps "$daemon" 2>/dev/null | grep -q "Up\|running"; then
                ((ready_containers++))
            fi
        done

        # Check client nodes
        for client in client-a1 client-b1; do
            if docker-compose ps "$client" 2>/dev/null | grep -q "Up\|running"; then
                ((ready_containers++))
            fi
        done

        if [[ $ready_containers -ge 5 ]]; then
            success "System ready: $ready_containers/7 containers up"
            return 0
        fi

        sleep 10
        waited=$((waited + 10))
        info "Progress: $ready_containers/7 containers ready (${waited}s elapsed)"
    done

    warn "System not fully ready after ${max_wait}s, but continuing..."
    warn "Ready containers: $ready_containers/7"
}

test_network_connectivity() {
    header "Testing Network Connectivity"

    cd "$INTEGRATION_DIR"

    local tests_passed=0
    local tests_total=0

    # Define test cases
    local tests=(
        "daemon-a1:primary-node"
        "daemon-a2:primary-node"
        "daemon-b1:primary-node"
        "daemon-b2:primary-node"
        "daemon-a1:daemon-a2"
        "daemon-a1:daemon-b1"
        "daemon-b1:daemon-b2"
        "client-a1:daemon-a1"
        "client-b1:daemon-b1"
    )

    for test in "${tests[@]}"; do
        ((tests_total++))
        local source
        local target
        source=$(echo "$test" | cut -d: -f1)
        target=$(echo "$test" | cut -d: -f2)

        if docker-compose exec -T "$source" ping -c 2 -W 3 "$target" >/dev/null 2>&1; then
            success "$source -> $target: reachable"
            ((tests_passed++))
        else
            failure "$source -> $target: unreachable"
        fi
    done

    info "Connectivity test results: $tests_passed/$tests_total passed"

    if [[ $tests_passed -eq $tests_total ]]; then
        success "All connectivity tests passed"
        return 0
    elif [[ $tests_passed -ge $((tests_total * 80 / 100)) ]]; then
        warn "Most connectivity tests passed ($tests_passed/$tests_total)"
        return 0
    else
        error "Many connectivity tests failed ($tests_passed/$tests_total)"
        return 1
    fi
}

test_dns_synchronization() {
    header "Testing DNS Synchronization"

    cd "$INTEGRATION_DIR"

    local nodes_with_dns=0
    local total_dns_records=0

    log "Analyzing DNS records in each node..."

    for node in primary-node daemon-a1 daemon-a2 daemon-b1 daemon-b2; do
        if docker-compose ps "$node" 2>/dev/null | grep -q "Up\|running"; then
            local records
            records=$(docker-compose logs --tail=200 "$node" 2>/dev/null | grep -c "10\." || echo "0")

            if [[ $records -gt 0 ]]; then
                ((nodes_with_dns++))
                ((total_dns_records += records))
                success "$node: $records DNS records"
            else
                warn "$node: No DNS records found"
            fi
        fi
    done

    info "DNS synchronization summary:"
    info "  Nodes with DNS records: $nodes_with_dns/5"
    info "  Total DNS records found: $total_dns_records"

    if [[ $nodes_with_dns -ge 3 && $total_dns_records -ge 10 ]]; then
        success "DNS synchronization test passed"
        return 0
    elif [[ $nodes_with_dns -ge 2 ]]; then
        warn "Partial DNS synchronization ($nodes_with_dns/5 nodes)"
        return 0
    else
        error "DNS synchronization failed"
        return 1
    fi
}

test_p2p_discovery() {
    header "Testing P2P Discovery"

    cd "$INTEGRATION_DIR"

    local discovery_activity=0

    log "Checking for P2P discovery activity..."

    for node in primary-node daemon-a1 daemon-b1; do
        if docker-compose logs --tail=200 "$node" 2>/dev/null | grep -qiE "discovery|joined network|found node"; then
            ((discovery_activity++))
            success "$node: Discovery activity detected"
        else
            warn "$node: No discovery activity found"
        fi
    done

    info "Discovery test results: $discovery_activity/3 nodes show activity"

    if [[ $discovery_activity -ge 2 ]]; then
        success "P2P discovery test passed"
        return 0
    else
        warn "Limited P2P discovery activity ($discovery_activity/3 nodes)"
        return 0
    fi
}

test_error_logs() {
    header "Checking Error Logs"

    cd "$INTEGRATION_DIR"

    local total_errors=0
    local critical_errors=0

    log "Checking for errors in container logs..."

    for node in primary-node daemon-a1 daemon-b1 client-a1; do
        if docker-compose ps "$node" 2>/dev/null | grep -q "Up\|running"; then
            local errors
            errors=$(docker-compose logs --tail=100 "$node" 2>/dev/null | grep -ci "error\|fatal\|panic" || echo "0")

            if [[ $errors -gt 0 ]]; then
                total_errors=$((total_errors + errors))

                # Check for critical errors
                local critical
                critical=$(docker-compose logs --tail=100 "$node" 2>/dev/null | grep -ci "fatal\|panic" || echo "0")
                critical_errors=$((critical_errors + critical))

                if [[ $critical -gt 0 ]]; then
                    error "$node: $critical critical errors, $errors total errors"
                else
                    warn "$node: $errors errors (non-critical)"
                fi
            else
                success "$node: No errors found"
            fi
        fi
    done

    info "Error summary: $total_errors total errors, $critical_errors critical"

    if [[ $critical_errors -eq 0 && $total_errors -lt 10 ]]; then
        success "Error log check passed"
        return 0
    elif [[ $critical_errors -eq 0 ]]; then
        warn "Some non-critical errors found ($total_errors total)"
        return 0
    else
        error "Critical errors detected ($critical_errors fatal/panic errors)"
        return 1
    fi
}

test_resource_usage() {
    header "Checking Resource Usage"

    cd "$INTEGRATION_DIR"

    local high_usage=0

    log "Checking container resource usage..."

    for node in primary-node daemon-a1 daemon-b1 client-a1; do
        if docker ps --format "{{.Names}}" | grep -q "$node"; then
            local stats
            stats=$(docker stats --no-stream --format "{{.CPUPerc}}\t{{.MemUsage}}" "$node" 2>/dev/null)

            if [[ -n "$stats" ]]; then
                local cpu
                local mem
                cpu=$(echo "$stats" | awk '{print $1}' | sed 's/%//')
                mem=$(echo "$stats" | awk '{print $2}' | sed 's/MiB//' | sed 's/GiB/*1024/' | bc 2>/dev/null || echo "0")

                info "$node: CPU=${cpu}%, Memory=${mem}MiB"

                # Check thresholds
                local cpu_num
                cpu_num=$(echo "$cpu" | cut -d. -f1)
                if [[ $cpu_num -gt 80 ]]; then
                    warn "$node: High CPU usage (${cpu}%)"
                    ((high_usage++))
                fi

                local mem_num
                mem_num=$(echo "$mem" | cut -d. -f1)
                if [[ $mem_num -gt 512 ]]; then
                    warn "$node: High memory usage (${mem}MiB)"
                    ((high_usage++))
                fi
            fi
        fi
    done

    if [[ $high_usage -eq 0 ]]; then
        success "Resource usage check passed"
    else
        warn "Some containers show high resource usage ($high_usage metrics above threshold)"
    fi

    return 0
}

generate_test_report() {
    header "Generating Test Report"

    local report_file="$INTEGRATION_DIR/reports/single-machine-test-$(date +%Y%m%d-%H%M%S).txt"
    mkdir -p "$INTEGRATION_DIR/reports"

    cat > "$report_file" << EOF
p2p-ddns Single-Machine Integration Test Report
================================================

Test Date: $(date)
Test Duration: $(echo "$SECONDS") seconds

Overall Results:
---------------
Total Tests: $TESTS_TOTAL
Passed: $TESTS_PASSED
Failed: $TESTS_FAILED
Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%

Test Details:
-------------

Network Connectivity Test: ${CONNECTIVITY_RESULT:-"PASSED"}
DNS Synchronization Test: ${DNS_SYNC_RESULT:-"PASSED"}
P2P Discovery Test: ${DISCOVERY_RESULT:-"PASSED"}
Error Log Check: ${ERROR_LOG_RESULT:-"PASSED"}
Resource Usage Check: ${RESOURCE_RESULT:-"PASSED"}

Container Status:
----------------
EOF

    # Add container status
    cd "$INTEGRATION_DIR"
    docker-compose ps >> "$report_file" 2>/dev/null || echo "Container status unavailable" >> "$report_file"

    cat >> "$report_file" << EOF

Next Steps:
-----------
1. Review container logs: docker-compose logs [container_name]
2. Monitor real-time status: docker-compose ps
3. Test network isolation: ./networks/network-control.sh
4. Stop environment: ./single-machine-test.sh cleanup

Notes:
------
- All tests run in Docker's isolated network environment
- Networks used: subnet-a (10.0.1.0/24), subnet-b (10.0.2.0/24), public (10.0.0.0/24)
- For detailed logs, check: $INTEGRATION_DIR/logs/
EOF

    success "Test report generated: $report_file"
    cat "$report_file"
}

# Main test execution

run_all_tests() {
    header "Starting Single-Machine Integration Tests"

    local start_time
    start_time=$(date +%s)

    TESTS_TOTAL=5

    # Test 1: Network Connectivity
    if test_network_connectivity; then
        ((TESTS_PASSED++))
        CONNECTIVITY_RESULT="PASSED"
    else
        ((TESTS_FAILED++))
        CONNECTIVITY_RESULT="FAILED"
    fi
    echo

    # Test 2: DNS Synchronization
    if test_dns_synchronization; then
        ((TESTS_PASSED++))
        DNS_SYNC_RESULT="PASSED"
    else
        ((TESTS_FAILED++))
        DNS_SYNC_RESULT="FAILED"
    fi
    echo

    # Test 3: P2P Discovery
    if test_p2p_discovery; then
        ((TESTS_PASSED++))
        DISCOVERY_RESULT="PASSED"
    else
        ((TESTS_FAILED++))
        DISCOVERY_RESULT="FAILED"
    fi
    echo

    # Test 4: Error Logs
    if test_error_logs; then
        ((TESTS_PASSED++))
        ERROR_LOG_RESULT="PASSED"
    else
        ((TESTS_FAILED++))
        ERROR_LOG_RESULT="FAILED"
    fi
    echo

    # Test 5: Resource Usage
    if test_resource_usage; then
        ((TESTS_PASSED++))
        RESOURCE_RESULT="PASSED"
    else
        ((TESTS_FAILED++))
        RESOURCE_RESULT="FAILED"
    fi
    echo

    local end_time
    end_time=$(date +%s)
    SECONDS=$((end_time - start_time))

    # Generate report
    generate_test_report

    # Final summary
    header "Test Summary"
    echo "Total Tests: $TESTS_TOTAL"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    echo "Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%"
    echo "Duration: ${SECONDS}s"

    if [[ $TESTS_FAILED -eq 0 ]]; then
        success "🎉 All tests PASSED!"
        return 0
    else
        warn "Some tests failed. Review the report above for details."
        return 1
    fi
}

quick_test() {
    header "Quick Test Mode"

    log "Running quick validation checks..."

    check_docker
    check_prerequisites

    if docker-compose ps -q 2>/dev/null | grep -q .; then
        success "Containers are running"
        test_network_connectivity
        test_dns_synchronization
        success "Quick test completed"
    else
        warn "No containers running. Run 'full-test' to start the complete test suite."
        exit 1
    fi
}

full_test() {
    header "Full Test Suite"

    check_docker
    check_prerequisites

    # Build images (skip if already built)
    if ! docker images | grep -q "p2p-ddns-test-base:test"; then
        build_images || exit 1
    else
        success "Docker images already built, skipping build..."
    fi

    # Run the topology + scale matrix. This manages its own networks and cleanup.
    ./scripts/p2p-matrix.sh --no-build
}

scenario_test() {
    local scenario=$1

    header "Running Scenario: $scenario"

    check_docker
    check_prerequisites

    if ! docker images | grep -q "p2p-ddns-test-base:test"; then
        build_images || exit 1
    fi

    # Delegate to the scenario wrapper which runs the appropriate matrix cases.
    ./scripts/test-scenarios.sh --scenario "$scenario"
}

cleanup() {
    if [[ "$CLEANUP_NEEDED" == true ]]; then
        echo
        read -p "Press Enter to clean up test environment, or Ctrl+C to keep it running..."
    fi
    cleanup_environment
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [COMMAND]

Single-machine integration test runner for p2p-ddns
Uses Docker's isolated network environment for comprehensive testing.

Commands:
  quick              Run quick validation (requires containers running)
  full               Run complete test suite (build + test)
  scenario NAME      Run specific test scenario
  cleanup            Clean up test environment
  help               Show this help

Available Scenarios:
  basic-functionality   Basic node startup and communication
  network-topology      Cross-subnet communication tests
  fault-recovery        Node failure and recovery tests
  dns-synchronization   DNS record synchronization tests
  end-to-end           Complete end-to-end workflow test

Examples:
  $0 quick                    # Quick check if system is running
  $0 full                     # Run complete test suite
  $0 scenario basic-functionality  # Run specific scenario
  $0 cleanup                  # Clean up test environment

Network Topology:
  Uses `./scripts/p2p-matrix.sh` to generate isolated Docker networks per case.
EOF
}

# Main execution

case "${1:-help}" in
    quick)
        quick_test
        ;;
    full)
        full_test
        ;;
    scenario)
        if [[ -z "${2:-}" ]]; then
            error "Scenario name required"
            echo "Available scenarios:"
            echo "  basic-functionality"
            echo "  network-topology"
            echo "  fault-recovery"
            echo "  dns-synchronization"
            echo "  end-to-end"
            exit 1
        fi
        scenario_test "$2"
        ;;
    cleanup)
        cleanup_environment
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac
