#!/bin/bash

# Main test runner for p2p-ddns integration tests

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
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Test configuration
DEFAULT_TIMEOUT=600
DEFAULT_LOG_LEVEL=info
DEFAULT_SCENARIOS="basic-functionality,network-topology,fault-recovery"

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
    echo -e "${PURPLE}=== $1 ===${NC}"
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "p2p-ddns Integration Test Runner"
    echo
    echo "Options:"
    echo "  --scenarios LIST      Comma-separated list of test scenarios"
    echo "  --timeout SECONDS     Test timeout (default: $DEFAULT_TIMEOUT)"
    echo "  --log-level LEVEL     Log level (debug|info|warn|error)"
    echo "  --build               Build images before testing"
    echo "  --cleanup-only        Only cleanup test environment"
    echo "  --no-cleanup          Don't cleanup after tests"
    echo "  --report-dir DIR      Custom report directory"
    echo "  --parallel            Run scenarios in parallel (experimental)"
    echo "  --dry-run             Show what would be executed"
    echo "  --help                Show this help"
    echo
    echo "Available Scenarios:"
    echo "  basic-functionality   Basic node startup and communication"
    echo "  network-topology      Cross-subnet communication tests"
    echo "  fault-recovery        Node failure and recovery tests"
    echo "  performance-stress    Performance and stress tests"
    echo "  configuration-changes Dynamic configuration tests"
    echo "  compatibility         Version compatibility tests"
    echo "  all                   Run all scenarios"
    echo
    echo "Examples:"
    echo "  $0                                    # Run default scenarios"
    echo "  $0 --scenarios basic-functionality   # Run single scenario"
    echo "  $0 --build --timeout 1200           # Build and run with longer timeout"
    echo "  $0 --cleanup-only                    # Only cleanup"
}

# Parse command line arguments
parse_args() {
    SCENARIOS="$DEFAULT_SCENARIOS"
    TIMEOUT="$DEFAULT_TIMEOUT"
    LOG_LEVEL="$DEFAULT_LOG_LEVEL"
    BUILD_IMAGES=false
    CLEANUP_ONLY=false
    NO_CLEANUP=false
    REPORT_DIR="$INTEGRATION_DIR/reports"
    PARALLEL=false
    DRY_RUN=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --scenarios)
                SCENARIOS="$2"
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
            --build)
                BUILD_IMAGES=true
                shift
                ;;
            --cleanup-only)
                CLEANUP_ONLY=true
                shift
                ;;
            --no-cleanup)
                NO_CLEANUP=true
                shift
                ;;
            --report-dir)
                REPORT_DIR="$2"
                shift 2
                ;;
            --parallel)
                PARALLEL=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Validate environment
validate_environment() {
    log "Validating test environment..."

    # Check if we're in the right directory
    if [[ ! -f "$INTEGRATION_DIR/docker-compose.yml" ]]; then
        error "Could not find docker-compose.yml in integration directory"
        exit 1
    fi

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed or not in PATH"
        exit 1
    fi

    # Check if Docker Compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        error "Docker Compose is not installed or not in PATH"
        exit 1
    fi

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running"
        exit 1
    fi

    # Create report directory
    mkdir -p "$REPORT_DIR"
    mkdir -p "$INTEGRATION_DIR/logs"

    log "Environment validation passed"
}

# Build Docker images
build_images() {
    if [[ "$BUILD_IMAGES" == true ]]; then
        log "Building Docker images..."

        if [[ "$DRY_RUN" == true ]]; then
            info "DRY RUN: Would build Docker images"
            return 0
        fi

        if ! "$SCRIPT_DIR/build-images.sh" build --tag test; then
            error "Failed to build Docker images"
            exit 1
        fi

        log "Docker images built successfully"
    fi
}

# Setup test environment
setup_environment() {
    log "Setting up test environment..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY RUN: Would setup test environment"
        return 0
    fi

    # Cleanup any existing environment
    cleanup_environment

    # Create Docker networks
    if ! "$INTEGRATION_DIR/networks/create-networks.sh" create; then
        error "Failed to create Docker networks"
        exit 1
    fi

    log "Test environment setup completed"
}

# Cleanup test environment
cleanup_environment() {
    log "Cleaning up test environment..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY RUN: Would cleanup test environment"
        return 0
    fi

    # Stop and remove containers
    cd "$INTEGRATION_DIR"
    if docker-compose ps -q | grep -q .; then
        docker-compose down --remove-orphans --timeout 30 || true
    fi

    # Remove Docker networks
    "$INTEGRATION_DIR/networks/cleanup-networks.sh" normal || true

    # Clean up network control rules
    if command -v "$INTEGRATION_DIR/networks/network-control.sh" &> /dev/null; then
        "$INTEGRATION_DIR/networks/network-control.sh" cleanup || true
    fi

    log "Test environment cleanup completed"
}

# Run test scenarios
run_scenarios() {
    local scenarios_array
    IFS=',' read -ra scenarios_array <<< "$SCENARIOS"

    local total_scenarios=${#scenarios_array[@]}
    local passed_scenarios=0
    local failed_scenarios=0
    local start_time
    start_time=$(date +%s)

    header "Running $total_scenarios test scenarios"

    # Create results file
    local results_file="$REPORT_DIR/test-results-$(date +%Y%m%d-%H%M%S).json"
    echo '{"scenarios": []}' > "$results_file"

    for scenario in "${scenarios_array[@]}"; do
        scenario=$(echo "$scenario" | xargs) # Trim whitespace

        if [[ "$scenario" == "all" ]]; then
            # Run all available scenarios
            run_all_scenarios
            return $?
        fi

        header "Running scenario: $scenario"

        local scenario_start_time
        scenario_start_time=$(date +%s)

        if [[ "$DRY_RUN" == true ]]; then
            info "DRY RUN: Would run scenario: $scenario"
            echo "  Would start at $(date)"
            echo "  Would timeout after ${TIMEOUT}s"
            echo
            continue
        fi

        # Run the scenario
        local scenario_log_file="$REPORT_DIR/${scenario}-$(date +%Y%m%d-%H%M%S).log"
        local scenario_passed=false

        if timeout "$TIMEOUT" "$SCRIPT_DIR/test-scenarios.sh" \
            --scenario="$scenario" \
            --timeout="$TIMEOUT" \
            --log-level="$LOG_LEVEL" \
            > "$scenario_log_file" 2>&1; then

            log "Scenario PASSED: $scenario"
            ((passed_scenarios++))
            scenario_passed=true
        else
            local exit_code=$?
            if [[ $exit_code -eq 124 ]]; then
                error "Scenario FAILED (timeout): $scenario"
            else
                error "Scenario FAILED (exit code $exit_code): $scenario"
            fi
            ((failed_scenarios++))
        fi

        local scenario_end_time
        scenario_end_time=$(date +%s)
        local scenario_duration=$((scenario_end_time - scenario_start_time))

        # Update results JSON
        local temp_results
        temp_results=$(mktemp)
        jq --arg scenario "$scenario" \
           --arg passed "$scenario_passed" \
           --arg duration "$scenario_duration" \
           --arg log_file "$(basename "$scenario_log_file")" \
           '.scenarios += [{"name": $scenario, "passed": ($passed == "true"), "duration": ($duration | tonumber), "log_file": $log_file}]' \
           "$results_file" > "$temp_results"
        mv "$temp_results" "$results_file"

        # Show brief summary
        echo "  Duration: ${scenario_duration}s"
        echo "  Log file: $scenario_log_file"
        echo

        # Add delay between scenarios
        sleep 5
    done

    # Generate final report
    generate_final_report "$start_time" "$passed_scenarios" "$failed_scenarios" "$results_file"

    # Return appropriate exit code
    if [[ $failed_scenarios -eq 0 ]]; then
        log "All scenarios passed!"
        return 0
    else
        error "$failed_scenarios scenario(s) failed"
        return 1
    fi
}

# Run all available scenarios
run_all_scenarios() {
    local all_scenarios="basic-functionality,network-topology,fault-recovery,performance-stress,configuration-changes,compatibility"

    # Temporarily update SCENARIOS and re-run
    local original_scenarios="$SCENARIOS"
    SCENARIOS="$all_scenarios"
    run_scenarios
    local exit_code=$?
    SCENARIOS="$original_scenarios"

    return $exit_code
}

# Generate final test report
generate_final_report() {
    local start_time="$1"
    local passed_scenarios="$2"
    local failed_scenarios="$3"
    local results_file="$4"

    local end_time
    end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    local total_scenarios=$((passed_scenarios + failed_scenarios))

    # Create HTML report
    local html_report="$REPORT_DIR/test-report-$(date +%Y%m%d-%H%M%S).html"

    cat > "$html_report" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>p2p-ddns Integration Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .passed { color: green; font-weight: bold; }
        .failed { color: red; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>p2p-ddns Integration Test Report</h1>
        <p class="timestamp">Generated on $(date)</p>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <p>Total Scenarios: $total_scenarios</p>
        <p class="passed">Passed: $passed_scenarios</p>
        <p class="failed">Failed: $failed_scenarios</p>
        <p>Total Duration: ${total_duration}s</p>
    </div>

    <h2>Scenario Results</h2>
    <table>
        <tr>
            <th>Scenario</th>
            <th>Result</th>
            <th>Duration (s)</th>
            <th>Log File</th>
        </tr>
EOF

    # Add scenario results to table
    jq -r '.scenarios[] | "\(.name)|\(.passed)|\(.duration)|\(.log_file)"' "$results_file" | while IFS='|' read -r name passed duration log_file; do
        local result_class="passed"
        local result_text="PASSED"
        if [[ "$passed" == "false" ]]; then
            result_class="failed"
            result_text="FAILED"
        fi

        cat >> "$html_report" << EOF
        <tr>
            <td>$name</td>
            <td class="$result_class">$result_text</td>
            <td>$duration</td>
            <td><a href="$log_file">$log_file</a></td>
        </tr>
EOF
    done

    cat >> "$html_report" << EOF
    </table>
</body>
</html>
EOF

    log "Test report generated: $html_report"
    log "Test results JSON: $results_file"
}

# Main execution
main() {
    header "p2p-ddns Integration Test Runner"
    echo "Started at: $(date)"
    echo

    parse_args "$@"

    if [[ "$CLEANUP_ONLY" == true ]]; then
        cleanup_environment
        exit 0
    fi

    validate_environment
    build_images
    setup_environment

    # Set trap for cleanup
    if [[ "$NO_CLEANUP" == false ]]; then
        trap cleanup_environment EXIT
    fi

    run_scenarios
    local exit_code=$?

    echo
    header "Test Run Completed"
    echo "Finished at: $(date)"

    if [[ $exit_code -eq 0 ]]; then
        log "All tests passed! 🎉"
    else
        error "Some tests failed. Check the reports for details."
    fi

    exit $exit_code
}

# Run main function with all arguments
main "$@"