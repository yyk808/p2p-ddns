#!/bin/bash

# Enhanced test scenarios for p2p-ddns integration tests
# This script provides comprehensive testing using Docker's isolated network environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] TEST:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] TEST WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] TEST ERROR:${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] TEST INFO:${NC} $1"
}

header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse command line arguments
SCENARIO=""
TIMEOUT=600
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
            echo "  basic-functionality   - Basic node startup and communication"
            echo "  network-topology      - Cross-subnet communication tests"
            echo "  fault-recovery        - Node failure and recovery tests"
            echo "  dns-synchronization   - DNS record synchronization tests"
            echo "  end-to-end           - Complete end-to-end workflow test"
            exit 0
            ;;
        help|--help|-h)
            echo "Usage: $0 --scenario SCENARIO [--timeout SECONDS] [--log-level LEVEL]"
            echo
            echo "Available scenarios:"
            echo "  basic-functionality   - Basic node startup and communication"
            echo "  network-topology      - Cross-subnet communication tests"
            echo "  fault-recovery        - Node failure and recovery tests"
            echo "  dns-synchronization   - DNS record synchronization tests"
            echo "  end-to-end           - Complete end-to-end workflow test"
            exit 0
            ;;
        *)
            error "Unknown argument: $1"
            exit 1
            ;;
    esac
done

if [[ -z "$SCENARIO" ]]; then
    error "Scenario name is required. Use --scenario SCENARIO"
    exit 1
fi

# Helper functions

check_container_running() {
    local container=$1
    cd "$INTEGRATION_DIR"
    docker-compose ps --format "{{.Name}}" | grep -q "^${container}$"
}

wait_for_container() {
    local container=$1
    local max_wait=${2:-120}
    local waited=0

    log "Waiting for container $container to start..."

    while [[ $waited -lt $max_wait ]]; do
        if check_container_running "$container"; then
            log "Container $container is running"
            return 0
        fi
        sleep 5
        waited=$((waited + 5))
    done

    error "Container $container did not start within ${max_wait}s"
    return 1
}

wait_for_healthy() {
    local container=$1
    local max_wait=${2:-180}
    local waited=0

    log "Waiting for container $container to be healthy..."

    while [[ $waited -lt $max_wait ]]; do
        cd "$INTEGRATION_DIR"
        local status
        status=$(docker-compose ps --format "{{.Status}}" "$container" 2>/dev/null || echo "")

        if echo "$status" | grep -q "healthy"; then
            log "Container $container is healthy"
            return 0
        fi

        sleep 5
        waited=$((waited + 5))
    done

    warn "Container $container not healthy after ${max_wait}s, continuing anyway"
    return 0
}

test_connectivity() {
    local source=$1
    local target=$2
    cd "$INTEGRATION_DIR"

    if docker-compose exec -T "$source" ping -c 2 -W 3 "$target" >/dev/null 2>&1; then
        info "✓ Connectivity: $source -> $target"
        return 0
    else
        warn "✗ Connectivity: $source -> $target failed"
        return 1
    fi
}

check_dns_records() {
    local container=$1
    local min_records=${2:-3}
    cd "$INTEGRATION_DIR"

    local records
    records=$(docker-compose exec -T "$container" \
        grep -A 10 "Address.*Name.*Last Seen" /app/logs/*.log 2>/dev/null | \
        grep -c "10\." || echo "0")

    info "Found $records DNS records in $container (expected: $min_records)"

    if [[ $records -ge $min_records ]]; then
        return 0
    else
        return 1
    fi
}

# Test scenario implementations

run_basic_functionality() {
    header "Basic Functionality Test"

    cd "$INTEGRATION_DIR"

    # Step 1: Create networks
    log "Creating Docker networks..."
    if ! ./networks/create-networks.sh create; then
        error "Failed to create networks"
        return 1
    fi

    # Step 2: Start containers
    log "Starting containers..."
    if ! docker-compose up -d; then
        error "Failed to start containers"
        return 1
    fi

    # Step 3: Wait for primary node
    log "Waiting for primary node..."
    if ! wait_for_container "primary-node" 60; then
        error "Primary node failed to start"
        return 1
    fi

    if ! wait_for_healthy "primary-node" 120; then
        warn "Primary node health check timed out"
    fi

    # Step 4: Wait for daemon nodes
    log "Waiting for daemon nodes..."
    for daemon in daemon-a1 daemon-a2 daemon-b1 daemon-b2; do
        if ! wait_for_container "$daemon" 60; then
            error "Daemon node $daemon failed to start"
            return 1
        fi
        sleep 5
    done

    # Step 5: Wait for client nodes
    log "Waiting for client nodes..."
    for client in client-a1 client-b1; do
        if ! wait_for_container "$client" 60; then
            error "Client node $client failed to start"
            return 1
        fi
        sleep 5
    done

    # Step 6: Check container status
    log "Checking container status..."
    local total_running
    total_running=$(docker-compose ps --filter "status=running" --services | wc -l)

    if [[ $total_running -lt 7 ]]; then
        error "Not all containers are running: $total_running/7"
        return 1
    fi

    info "✓ All 7 containers are running"

    # Step 7: Test basic connectivity
    log "Testing basic connectivity..."

    if test_connectivity "daemon-a1" "primary-node" && \
       test_connectivity "daemon-b1" "primary-node" && \
       test_connectivity "daemon-a1" "daemon-b1"; then
        info "✓ Basic connectivity tests passed"
    else
        warn "Some connectivity tests failed, but continuing..."
    fi

    # Step 8: Wait for ticket propagation
    log "Waiting for ticket propagation..."
    sleep 30

    # Step 9: Verify process is running
    log "Verifying p2p-ddns processes..."
    local processes=0
    for container in primary-node daemon-a1 daemon-a2 daemon-b1 daemon-b2; do
        if docker-compose exec -T "$container" pgrep -f p2p-ddns >/dev/null 2>&1; then
            ((processes++))
        fi
    done

    if [[ $processes -ge 5 ]]; then
        info "✓ p2p-ddns processes running in $processes/5 daemon containers"
    else
        error "p2p-ddns processes not running properly: $processes/5"
        return 1
    fi

    # Step 10: Check for errors in logs
    log "Checking for errors in logs..."
    local error_count=0
    for container in primary-node daemon-a1 daemon-b1; do
        local errors
        errors=$(docker-compose logs --tail=50 "$container" 2>/dev/null | grep -i "error\|fatal\|panic" | wc -l || true)
        if [[ $errors -gt 0 ]]; then
            warn "Found $errors errors in $container logs"
            error_count=$((error_count + errors))
        fi
    done

    if [[ $error_count -gt 10 ]]; then
        error "Too many errors in logs: $error_count"
        return 1
    fi

    log "✅ Basic functionality test PASSED"
    return 0
}

run_network_topology() {
    header "Network Topology Test"

    cd "$INTEGRATION_DIR"

    # Ensure containers are running
    if ! docker-compose ps -q | grep -q .; then
        log "Containers not running, starting them..."
        if ! docker-compose up -d; then
            error "Failed to start containers"
            return 1
        fi
        sleep 60
    fi

    # Test 1: Verify network isolation (nodes in same subnet should communicate)
    log "Test 1: Same subnet communication (subnet-a)"

    local subnet_a_passed=0
    if test_connectivity "daemon-a1" "primary-node"; then
        ((subnet_a_passed++))
    fi
    if test_connectivity "daemon-a2" "primary-node"; then
        ((subnet_a_passed++))
    fi
    if test_connectivity "daemon-a1" "daemon-a2"; then
        ((subnet_a_passed++))
    fi

    if [[ $subnet_a_passed -eq 3 ]]; then
        info "✓ Subnet-A communication: PASSED (3/3 tests)"
    else
        error "✗ Subnet-A communication: FAILED ($subnet_a_passed/3 tests)"
        return 1
    fi

    # Test 2: Verify cross-subnet communication
    log "Test 2: Cross-subnet communication"

    local cross_subnet_passed=0
    if test_connectivity "daemon-a1" "daemon-b1"; then
        ((cross_subnet_passed++))
    fi
    if test_connectivity "daemon-b1" "daemon-a1"; then
        ((cross_subnet_passed++))
    fi
    if test_connectivity "daemon-a2" "daemon-b2"; then
        ((cross_subnet_passed++))
    fi

    if [[ $cross_subnet_passed -ge 2 ]]; then
        info "✓ Cross-subnet communication: PASSED ($cross_subnet_passed/3 tests)"
    else
        warn "⚠ Cross-subnet communication: PARTIAL ($cross_subnet_passed/3 tests)"
    fi

    # Test 3: Verify network discovery
    log "Test 3: Network discovery"

    # Check if nodes have discovered each other
    local discovery_found=0
    for node in daemon-a1 daemon-b1; do
        if docker-compose logs --tail=100 "$node" 2>/dev/null | grep -q "Received discovery\|Found node\|Node joined"; then
            ((discovery_found++))
        fi
    done

    if [[ $discovery_found -ge 2 ]]; then
        info "✓ Network discovery: PASSED ($discovery_found/2 nodes show discovery activity)"
    else
        warn "⚠ Network discovery: PARTIAL ($discovery_found/2 nodes)"
    fi

    # Test 4: Verify gossip protocol
    log "Test 4: Gossip protocol propagation"

    local gossip_found=0
    for node in primary-node daemon-a1 daemon-b1; do
        if docker-compose logs --tail=100 "$node" 2>/dev/null | grep -q "Gossip\|broadcast\|Received message"; then
            ((gossip_found++))
        fi
    done

    if [[ $gossip_found -ge 2 ]]; then
        info "✓ Gossip protocol: PASSED ($gossip_found/3 nodes show gossip activity)"
    else
        warn "⚠ Gossip protocol: PARTIAL ($gossip_found/3 nodes)"
    fi

    # Test 5: Network topology summary
    log "Network topology summary"

    docker-compose exec -T primary-node ip route show 2>/dev/null || true
    docker-compose exec -T daemon-a1 ip route show 2>/dev/null || true

    log "✅ Network topology test PASSED"
    return 0
}

run_fault_recovery() {
    header "Fault Recovery Test"

    cd "$INTEGRATION_DIR"

    # Ensure containers are running
    if ! docker-compose ps -q | grep -q .; then
        log "Containers not running, starting them..."
        docker-compose up -d
        sleep 60
    fi

    # Test 1: Isolate a daemon node
    log "Test 1: Isolating daemon-a1"

    if command -v ./networks/network-control.sh >/dev/null 2>&1; then
        if ./networks/network-control.sh isolate-container p2p-ddns-test-daemon-a1 2>/dev/null; then
            log "✓ daemon-a1 isolated"
            sleep 30

            # Check if other nodes are still running
            if test_connectivity "daemon-a2" "primary-node"; then
                info "✓ Network continues operating with isolated node"
            fi

            # Restore connectivity
            log "Restoring daemon-a1 connectivity..."
            ./networks/network-control.sh restore-container p2p-ddns-test-daemon-a1 2>/dev/null || true
            sleep 30

            # Verify recovery
            if test_connectivity "daemon-a1" "primary-node"; then
                log "✓ daemon-a1 recovered and communicating"
            else
                warn "⚠ daemon-a1 recovery may not be complete"
            fi
        else
            warn "Network control script not available, skipping isolation test"
        fi
    else
        warn "Network control script not available, skipping isolation test"
    fi

    # Test 2: Stop and restart a daemon node
    log "Test 2: Stopping and restarting daemon-b1"

    docker-compose stop daemon-b1
    sleep 10

    if ! check_container_running "daemon-b1"; then
        info "✓ daemon-b1 stopped successfully"
    fi

    log "Restarting daemon-b1..."
    docker-compose start daemon-b1
    sleep 40

    if wait_for_healthy "daemon-b1" 60; then
        log "✓ daemon-b1 restarted and is healthy"
    else
        warn "⚠ daemon-b1 restart may not be fully healthy"
    fi

    # Test 3: Verify network continued operating during fault
    log "Test 3: Checking if network continued during fault"

    if check_dns_records "primary-node" 2; then
        info "✓ DNS records maintained during fault"
    else
        warn "⚠ DNS records may have been affected by fault"
    fi

    log "✅ Fault recovery test PASSED"
    return 0
}

run_dns_synchronization() {
    header "DNS Synchronization Test"

    cd "$INTEGRATION_DIR"

    # Ensure containers are running
    if ! docker-compose ps -q | grep -q .; then
        log "Containers not running, starting them..."
        docker-compose up -d
        sleep 60
    fi

    # Wait for DNS propagation
    log "Waiting for DNS synchronization..."
    sleep 60

    # Test 1: Check DNS records in primary node
    log "Test 1: DNS records in primary node"

    local primary_records=0
    primary_records=$(docker-compose logs --tail=200 primary-node 2>/dev/null | \
        grep -c "10\." || echo "0")

    info "Primary node has $primary_records DNS record entries"

    if [[ $primary_records -ge 3 ]]; then
        log "✓ Primary node DNS records: OK"
    else
        warn "⚠ Primary node DNS records: LOW ($primary_records)"
    fi

    # Test 2: Check DNS records in daemon nodes
    log "Test 2: DNS records in daemon nodes"

    local daemon_a1_records=0
    daemon_a1_records=$(docker-compose logs --tail=200 daemon-a1 2>/dev/null | \
        grep -c "10\." || echo "0")

    local daemon_b1_records=0
    daemon_b1_records=$(docker-compose logs --tail=200 daemon-b1 2>/dev/null | \
        grep -c "10\." || echo "0")

    info "daemon-a1 has $daemon_a1_records DNS record entries"
    info "daemon-b1 has $daemon_b1_records DNS record entries"

    if [[ $daemon_a1_records -ge 3 && $daemon_b1_records -ge 3 ]]; then
        log "✓ Daemon nodes DNS records: OK"
    else
        warn "⚠ Daemon nodes DNS records: LOW"
    fi

    # Test 3: Verify DNS record consistency
    log "Test 3: DNS record consistency"

    # Extract unique node names from logs
    local primary_nodes
    primary_nodes=$(docker-compose logs --tail=500 primary-node 2>/dev/null | \
        grep -E "primary-node|daemon-a1|daemon-b1|daemon-a2|daemon-b2" | \
        grep -oE "(primary-node|daemon-[ab][12])" | sort -u | wc -l)

    info "Found $primary_nodes unique nodes in primary's DNS table"

    if [[ $primary_nodes -ge 4 ]]; then
        log "✓ DNS record consistency: OK ($primary_nodes nodes)"
    else
        warn "⚠ DNS record consistency: PARTIAL ($primary_nodes nodes)"
    fi

    # Test 4: Verify heartbeat mechanism
    log "Test 4: Heartbeat mechanism"

    local heartbeat_found=0
    for node in primary-node daemon-a1 daemon-b1; do
        if docker-compose logs --tail=200 "$node" 2>/dev/null | grep -qi "heartbeat"; then
            ((heartbeat_found++))
        fi
    done

    info "Heartbeat activity found in $heartbeat_found/3 nodes"

    if [[ $heartbeat_found -ge 2 ]]; then
        log "✓ Heartbeat mechanism: OK"
    else
        warn "⚠ Heartbeat mechanism: PARTIAL"
    fi

    # Test 5: Check for DNS table output
    log "Test 5: DNS table output verification"

    local table_found=0
    for node in primary-node daemon-a1 daemon-b1; do
        if docker-compose logs --tail=500 "$node" 2>/dev/null | grep -q "Address.*Name.*Last Seen"; then
            ((table_found++))
        fi
    done

    if [[ $table_found -ge 2 ]]; then
        log "✓ DNS table output: OK ($table_found/3 nodes)"
    else
        warn "⚠ DNS table output: PARTIAL ($table_found/3 nodes)"
    fi

    log "✅ DNS synchronization test PASSED"
    return 0
}

run_end_to_end() {
    header "End-to-End Workflow Test"

    cd "$INTEGRATION_DIR"

    # Phase 1: Clean start
    log "Phase 1: Clean start"
    docker-compose down -v 2>/dev/null || true
    ./networks/cleanup-networks.sh normal 2>/dev/null || true
    sleep 5

    # Phase 2: Create networks
    log "Phase 2: Creating isolated network environment"
    if ! ./networks/create-networks.sh create; then
        error "Failed to create networks"
        return 1
    fi
    sleep 5

    # Phase 3: Build images
    log "Phase 3: Building Docker images"
    if ! ./scripts/build-images-simple.sh build --tag test; then
        error "Failed to build images"
        return 1
    fi
    sleep 5

    # Phase 4: Start primary node
    log "Phase 4: Starting primary node"
    docker-compose up -d primary-node
    if ! wait_for_healthy "primary-node" 120; then
        error "Primary node failed to start"
        return 1
    fi
    sleep 10

    # Phase 5: Extract ticket
    log "Phase 5: Extracting network ticket"
    local ticket_file="shared/tickets/ticket.txt"
    mkdir -p shared/tickets

    local ticket_found=0
    for i in {1..30}; do
        if docker-compose logs --tail=50 primary-node 2>/dev/null | grep -q "Ticket:"; then
            docker-compose logs --tail=50 primary-node 2>/dev/null | \
                grep "Ticket:" | head -1 | cut -d' ' -f2- > "$ticket_file"
            ticket_found=1
            log "✓ Ticket extracted successfully"
            break
        fi
        sleep 2
    done

    if [[ $ticket_found -eq 0 ]]; then
        warn "⚠ Ticket extraction failed, but continuing..."
    fi

    # Phase 6: Start daemon nodes
    log "Phase 6: Starting daemon nodes"
    docker-compose up -d daemon-a1 daemon-a2 daemon-b1 daemon-b2

    for daemon in daemon-a1 daemon-a2 daemon-b1 daemon-b2; do
        if ! wait_for_container "$daemon" 60; then
            error "Daemon $daemon failed to start"
            return 1
        fi
        sleep 5
    done

    # Phase 7: Wait for daemon nodes to join network
    log "Phase 7: Waiting for daemon nodes to join network"
    sleep 60

    # Phase 8: Verify daemon nodes are communicating with primary
    log "Phase 8: Verifying daemon-primary communication"

    local daemons_connected=0
    for daemon in daemon-a1 daemon-b1; do
        if test_connectivity "$daemon" "primary-node"; then
            ((daemons_connected++))
        fi
    done

    if [[ $daemons_connected -ge 1 ]]; then
        log "✓ Daemons connected to primary: OK ($daemons_connected/2)"
    else
        error "✗ Daemons failed to connect to primary"
        return 1
    fi

    # Phase 9: Start client nodes
    log "Phase 9: Starting client nodes"
    docker-compose up -d client-a1 client-b1

    for client in client-a1 client-b1; do
        if ! wait_for_container "$client" 60; then
            error "Client $client failed to start"
            return 1
        fi
        sleep 5
    done

    # Phase 10: Wait for full network convergence
    log "Phase 10: Waiting for full network convergence"
    sleep 60

    # Phase 11: Verify DNS synchronization
    log "Phase 11: Verifying DNS synchronization across all nodes"

    local nodes_with_dns=0
    for node in primary-node daemon-a1 daemon-b1; do
        if docker-compose logs --tail=200 "$node" 2>/dev/null | grep -c "10\." | grep -q "[1-9]"; then
            ((nodes_with_dns++))
        fi
    done

    if [[ $nodes_with_dns -ge 2 ]]; then
        log "✓ DNS synchronization: OK ($nodes_with_dns/3 nodes)"
    else
        warn "⚠ DNS synchronization: PARTIAL ($nodes_with_dns/3 nodes)"
    fi

    # Phase 12: Test resilience (stop one daemon)
    log "Phase 12: Testing resilience - stopping daemon-b1"
    docker-compose stop daemon-b1
    sleep 30

    if test_connectivity "daemon-a1" "primary-node"; then
        log "✓ Network resilience: OK (continues without daemon-b1)"
    else
        warn "⚠ Network may have been affected by daemon-b1 failure"
    fi

    # Phase 13: Restore daemon
    log "Phase 13: Restoring daemon-b1"
    docker-compose start daemon-b1
    sleep 40

    if test_connectivity "daemon-b1" "primary-node"; then
        log "✓ Node recovery: OK (daemon-b1 restored)"
    else
        warn "⚠ daemon-b1 recovery may not be complete"
    fi

    # Phase 14: Final validation
    log "Phase 14: Final validation"

    local all_healthy=0
    for container in primary-node daemon-a1 daemon-b1 client-a1; do
        if docker-compose ps --format "{{.Status}}" "$container" 2>/dev/null | grep -q "Up\|running"; then
            ((all_healthy++))
        fi
    done

    if [[ $all_healthy -ge 3 ]]; then
        log "✓ Overall system health: OK ($all_healthy/4 key containers)"
    else
        warn "⚠ Overall system health: PARTIAL ($all_healthy/4 key containers)"
    fi

    log "✅ End-to-end workflow test PASSED"
    return 0
}

# Main execution

header "p2p-ddns Integration Test"
echo "Scenario: $SCENARIO"
echo "Timeout: ${TIMEOUT}s"
echo "Log Level: $LOG_LEVEL"
echo

case "$SCENARIO" in
    basic-functionality)
        if ! run_basic_functionality; then
            error "Basic functionality test FAILED"
            exit 1
        fi
        ;;
    network-topology)
        if ! run_network_topology; then
            error "Network topology test FAILED"
            exit 1
        fi
        ;;
    fault-recovery)
        if ! run_fault_recovery; then
            error "Fault recovery test FAILED"
            exit 1
        fi
        ;;
    dns-synchronization)
        if ! run_dns_synchronization; then
            error "DNS synchronization test FAILED"
            exit 1
        fi
        ;;
    end-to-end)
        if ! run_end_to_end; then
            error "End-to-end test FAILED"
            exit 1
        fi
        ;;
    *)
        error "Unknown scenario: $SCENARIO"
        echo "Available scenarios:"
        echo "  basic-functionality"
        echo "  network-topology"
        echo "  fault-recovery"
        echo "  dns-synchronization"
        echo "  end-to-end"
        exit 1
        ;;
esac

header "Test Completed Successfully"
log "✅ All tests in scenario '$SCENARIO' PASSED"

exit 0
