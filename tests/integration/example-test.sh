#!/bin/bash

# Simple test execution example for p2p-ddns
# Demonstrates how to run tests on a single machine with Docker

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] TEST:${NC} $1"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]]; then
    error "Please run this script from the project root directory"
    echo "Usage: ./tests/integration/example-test.sh"
    exit 1
fi

# Main test flow
main() {
    header "p2p-ddns Single-Machine Test Example"

    log "This script demonstrates running p2p-ddns tests on a single machine"
    log "using Docker's isolated network environment."

    echo

    # Step 1: Run quick test
    info "Step 1: Running quick validation check..."
    if ./test-integration.sh quick; then
        log "✓ Quick validation passed"
    else
        warn "⚠ Quick validation failed, containers may not be running"
        info "Will attempt to start environment now..."
    fi

    echo
    read -p "Press Enter to continue with full test or Ctrl+C to cancel..."

    # Step 2: Run full test
    header "Running Complete Test Suite"
    log "This will take 10-15 minutes..."

    if ./test-integration.sh full; then
        log "✅ All tests PASSED!"
    else
        error "❌ Some tests failed"
        exit 1
    fi

    echo

    # Step 3: Show results
    header "Test Results"

    log "Test reports are available in: tests/integration/reports/"

    echo
    log "Container status:"
    cd tests/integration
    docker-compose ps
    cd ../..

    echo
    info "To view logs: cd tests/integration && docker-compose logs"
    info "To clean up: ./test-integration.sh clean"
    info "To run specific scenarios: ./test-integration.sh scenario <name>"

    echo
    header "Test Completed"
}

# Run main function
main "$@"
