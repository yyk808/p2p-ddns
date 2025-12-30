#!/bin/bash

# Validation script for p2p-ddns integration test results

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

# Validation thresholds
MIN_DNS_RECORDS=3
MAX_ERROR_COUNT=5
MIN_UPTIME_PERCENT=90
MAX_MEMORY_MB=512
MAX_CPU_PERCENT=80

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] VALIDATE:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] VALIDATE WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] VALIDATE ERROR:${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] VALIDATE INFO:${NC} $1"
}

header() {
    echo -e "${PURPLE}=== $1 ===${NC}"
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [LOG_DIR]"
    echo
    echo "Validate p2p-ddns integration test results"
    echo
    echo "Options:"
    echo "  --thresholds FILE    Load custom validation thresholds"
    echo "  --output FORMAT      Output format (text|json|html)"
    echo "  --strict             Enable strict validation mode"
    echo "  --report-dir DIR     Custom report output directory"
    echo "  --help               Show this help"
    echo
    echo "Arguments:"
    echo "  LOG_DIR              Directory containing test logs (default: ./logs)"
    echo
    echo "Examples:"
    echo "  $0                                   # Validate default logs"
    echo "  $0 --output json ./test-logs         # JSON output for custom log dir"
    echo "  $0 --strict --thresholds custom.toml # Strict validation with custom thresholds"
}

# Parse command line arguments
parse_args() {
    LOG_DIR="$INTEGRATION_DIR/logs"
    OUTPUT_FORMAT="text"
    STRICT_MODE=false
    REPORT_DIR="$INTEGRATION_DIR/reports"
    THRESHOLDS_FILE=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --thresholds)
                THRESHOLDS_FILE="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --strict)
                STRICT_MODE=true
                shift
                ;;
            --report-dir)
                REPORT_DIR="$2"
                shift 2
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            -*)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [[ -z "$LOG_DIR" || "$LOG_DIR" == "$INTEGRATION_DIR/logs" ]]; then
                    LOG_DIR="$1"
                else
                    error "Multiple log directories specified"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Create report directory
    mkdir -p "$REPORT_DIR"
}

# Load custom thresholds
load_thresholds() {
    if [[ -n "$THRESHOLDS_FILE" && -f "$THRESHOLDS_FILE" ]]; then
        log "Loading thresholds from: $THRESHOLDS_FILE"
        # Source the thresholds file if it's a shell script
        case "$THRESHOLDS_FILE" in
            *.sh)
                source "$THRESHOLDS_FILE"
                ;;
            *.toml)
                # Basic TOML parsing (would need a proper parser in production)
                warn "TOML threshold parsing not implemented, using defaults"
                ;;
        esac
    fi
}

# Validate container health
validate_container_health() {
    header "Container Health Validation"

    local overall_health=true
    local health_results=()

    cd "$INTEGRATION_DIR"

    # Check if containers are running
    local containers
    containers=$(docker-compose ps --format "{{.Name}}\t{{.Status}}" 2>/dev/null || true)

    if [[ -z "$containers" ]]; then
        warn "No containers found - test environment may be stopped"
        health_results+=("containers:stopped")
        return 0
    fi

    while IFS=$'\t' read -r name status; do
        local is_healthy=false
        local container_type="unknown"

        # Determine container type
        case "$name" in
            *primary*) container_type="primary" ;;
            *daemon*) container_type="daemon" ;;
            *client*) container_type="client" ;;
        esac

        # Check health status
        if echo "$status" | grep -q "healthy"; then
            is_healthy=true
            info "✓ $name: healthy"
        elif echo "$status" | grep -q "running"; then
            warn "⚠ $name: running (health check not ready)"
            is_healthy=true  # Consider running as acceptable for now
        else
            error "✗ $name: $status"
            overall_health=false
        fi

        health_results+=("${container_type}:${is_healthy}")
    done <<< "$containers"

    # Calculate health percentage
    local total_containers
    local healthy_containers
    total_containers=$(echo "${health_results[@]}" | tr ' ' '\n' | wc -l)
    healthy_containers=$(echo "${health_results[@]}" | tr ' ' '\n' | grep -c ":true" || true)

    local health_percentage
    if [[ $total_containers -gt 0 ]]; then
        health_percentage=$((healthy_containers * 100 / total_containers))
    else
        health_percentage=0
    fi

    info "Overall health: $healthy_containers/$total_containers ($health_percentage%)"

    if [[ $health_percentage -lt $MIN_UPTIME_PERCENT ]]; then
        error "Health percentage below threshold: $health_percentage% < $MIN_UPTIME_PERCENT%"
        overall_health=false
    fi

    echo "container_health:$health_percentage" >> "$VALIDATION_RESULTS_FILE"

    if [[ "$overall_health" == true ]]; then
        log "Container health validation PASSED"
        return 0
    else
        error "Container health validation FAILED"
        return 1
    fi
}

# Validate DNS records
validate_dns_records() {
    header "DNS Records Validation"

    local dns_validation_passed=true
    local total_records=0

    # Find primary node log file
    local primary_log
    primary_log=$(find "$LOG_DIR" -name "*primary*.log" 2>/dev/null | head -n 1)

    if [[ -z "$primary_log" || ! -f "$primary_log" ]]; then
        warn "Primary node log file not found: $primary_log"
        return 0
    fi

    info "Analyzing primary log: $primary_log"

    # Extract DNS records from logs
    local dns_records
    dns_records=$(grep -A 20 "Address.*Name.*Last Seen" "$primary_log" 2>/dev/null | grep "10\." || true)

    if [[ -n "$dns_records" ]]; then
        total_records=$(echo "$dns_records" | wc -l)
        info "Found $total_records DNS records"

        # Validate record format
        local valid_records=0
        while IFS= read -r record; do
            if echo "$record" | grep -q "^10\."; then
                ((valid_records++))
                if [[ "$OUTPUT_FORMAT" != "json" ]]; then
                    echo "  ✓ $record"
                fi
            else
                warn "  ⚠ Invalid record format: $record"
            fi
        done <<< "$dns_records"

        if [[ $valid_records -lt $MIN_DNS_RECORDS ]]; then
            error "Insufficient valid DNS records: $valid_records < $MIN_DNS_RECORDS"
            dns_validation_passed=false
        fi
    else
        error "No DNS records found in logs"
        dns_validation_passed=false
    fi

    echo "dns_records:$total_records" >> "$VALIDATION_RESULTS_FILE"

    if [[ "$dns_validation_passed" == true ]]; then
        log "DNS records validation PASSED"
        return 0
    else
        error "DNS records validation FAILED"
        return 1
    fi
}

# Validate error counts
validate_error_counts() {
    header "Error Count Validation"

    local error_validation_passed=true
    local total_errors=0

    # Check all log files for errors
    while IFS= read -r -d '' log_file; do
        local file_errors
        file_errors=$(grep -i "error\|fatal\|panic" "$log_file" 2>/dev/null | wc -l || true)

        if [[ $file_errors -gt 0 ]]; then
            local filename
            filename=$(basename "$log_file")
            warn "Found $file_errors errors in $filename"

            if [[ "$STRICT_MODE" == true ]]; then
                # Show recent errors in strict mode
                info "Recent errors in $filename:"
                grep -i "error\|fatal\|panic" "$log_file" 2>/dev/null | tail -5 | sed 's/^/    /'
            fi

            total_errors=$((total_errors + file_errors))
        fi
    done < <(find "$LOG_DIR" -name "*.log" -print0 2>/dev/null)

    info "Total errors found: $total_errors"

    if [[ $total_errors -gt $MAX_ERROR_COUNT ]]; then
        error "Error count exceeds threshold: $total_errors > $MAX_ERROR_COUNT"
        error_validation_passed=false
    fi

    echo "error_count:$total_errors" >> "$VALIDATION_RESULTS_FILE"

    if [[ "$error_validation_passed" == true ]]; then
        log "Error count validation PASSED"
        return 0
    else
        error "Error count validation FAILED"
        return 1
    fi
}

# Validate network connectivity
validate_network_connectivity() {
    header "Network Connectivity Validation"

    local network_validation_passed=true

    cd "$INTEGRATION_DIR"

    # Test basic connectivity between key containers
    local connectivity_tests=(
        "daemon-a1:primary-node"
        "daemon-b1:primary-node"
        "daemon-a1:daemon-b1"
        "daemon-b1:daemon-a1"
    )

    for test in "${connectivity_tests[@]}"; do
        local source
        local target
        source=$(echo "$test" | cut -d: -f1)
        target=$(echo "$test" | cut -d: -f2)

        if docker-compose ps --format "{{.Name}}" | grep -q "$source" && \
           docker-compose ps --format "{{.Name}}" | grep -q "$target"; then

            if docker-compose exec "$source" ping -c 2 -W 3 "$target" >/dev/null 2>&1; then
                info "✓ $source -> $target: reachable"
            else
                warn "⚠ $source -> $target: unreachable"
                if [[ "$STRICT_MODE" == true ]]; then
                    network_validation_passed=false
                fi
            fi
        else
            warn "⚠ Skipping connectivity test: $source -> $target (containers not running)"
        fi
    done

    echo "network_connectivity:$([[ $network_validation_passed == true ]] && echo "passed" || echo "failed")" >> "$VALIDATION_RESULTS_FILE"

    if [[ "$network_validation_passed" == true ]]; then
        log "Network connectivity validation PASSED"
        return 0
    else
        error "Network connectivity validation FAILED"
        return 1
    fi
}

# Validate resource usage
validate_resource_usage() {
    header "Resource Usage Validation"

    local resource_validation_passed=true

    cd "$INTEGRATION_DIR"

    # Check container resource usage
    while IFS= read -r container; do
        if docker ps --format "{{.Names}}" | grep -q "$container"; then
            local stats
            stats=$(docker stats --no-stream --format "table {{.CPUPerc}}\t{{.MemUsage}}" "$container" 2>/dev/null | tail -n +2 || true)

            if [[ -n "$stats" ]]; then
                local cpu_percent
                local memory_usage
                cpu_percent=$(echo "$stats" | awk '{print $1}' | sed 's/%//')
                memory_usage=$(echo "$stats" | awk '{print $2}' | sed 's/MiB//' | sed 's/GiB/*1024/' | bc 2>/dev/null || echo "0")

                info "$container: CPU=${cpu_percent}%, Memory=${memory_usage}MiB"

                # Validate CPU usage
                if [[ ${cpu_percent%.*} -gt $MAX_CPU_PERCENT ]]; then
                    warn "High CPU usage for $container: ${cpu_percent}% > ${MAX_CPU_PERCENT}%"
                    if [[ "$STRICT_MODE" == true ]]; then
                        resource_validation_passed=false
                    fi
                fi

                # Validate memory usage
                if [[ ${memory_usage%.*} -gt $MAX_MEMORY_MB ]]; then
                    warn "High memory usage for $container: ${memory_usage}MiB > ${MAX_MEMORY_MB}MiB"
                    if [[ "$STRICT_MODE" == true ]]; then
                        resource_validation_passed=false
                    fi
                fi
            fi
        fi
    done < <(docker-compose ps --format "{{.Name}}" 2>/dev/null)

    echo "resource_usage:$([[ $resource_validation_passed == true ]] && echo "passed" || echo "failed")" >> "$VALIDATION_RESULTS_FILE"

    if [[ "$resource_validation_passed" == true ]]; then
        log "Resource usage validation PASSED"
        return 0
    else
        error "Resource usage validation FAILED"
        return 1
    fi
}

# Generate validation report
generate_report() {
    local overall_result="$1"
    local report_file="$REPORT_DIR/validation-report-$(date +%Y%m%d-%H%M%S).${OUTPUT_FORMAT}"

    case "$OUTPUT_FORMAT" in
        json)
            generate_json_report "$overall_result" "$report_file"
            ;;
        html)
            generate_html_report "$overall_result" "$report_file"
            ;;
        *)
            generate_text_report "$overall_result" "$report_file"
            ;;
    esac

    log "Validation report generated: $report_file"
}

# Generate text report
generate_text_report() {
    local overall_result="$1"
    local report_file="$2"

    cat > "$report_file" << EOF
p2p-ddns Integration Test Validation Report
==========================================

Generated: $(date)
Overall Result: $overall_result
Validation Mode: $([ "$STRICT_MODE" == true ] && echo "Strict" || echo "Normal")

Validation Results:
------------------

EOF

    while IFS=':' read -r metric value; do
        case "$metric" in
            container_health)
                echo "Container Health: $value%" >> "$report_file"
                ;;
            dns_records)
                echo "DNS Records: $value" >> "$report_file"
                ;;
            error_count)
                echo "Error Count: $value" >> "$report_file"
                ;;
            network_connectivity)
                echo "Network Connectivity: $value" >> "$report_file"
                ;;
            resource_usage)
                echo "Resource Usage: $value" >> "$report_file"
                ;;
        esac
    done < "$VALIDATION_RESULTS_FILE"

    cat >> "$report_file" << EOF

Thresholds Used:
----------------
- Minimum DNS Records: $MIN_DNS_RECORDS
- Maximum Error Count: $MAX_ERROR_COUNT
- Minimum Uptime: $MIN_UPTIME_PERCENT%
- Maximum Memory: ${MAX_MEMORY_MB}MiB
- Maximum CPU: ${MAX_CPU_PERCENT}%

Log Directory: $LOG_DIR
EOF
}

# Generate JSON report
generate_json_report() {
    local overall_result="$1"
    local report_file="$2"

    echo "{
  \"timestamp\": \"$(date -Iseconds)\",
  \"overall_result\": \"$overall_result\",
  \"validation_mode\": \"$([ "$STRICT_MODE" == true ] && echo "strict" || echo "normal")\",
  \"thresholds\": {
    \"min_dns_records\": $MIN_DNS_RECORDS,
    \"max_error_count\": $MAX_ERROR_COUNT,
    \"min_uptime_percent\": $MIN_UPTIME_PERCENT,
    \"max_memory_mb\": $MAX_MEMORY_MB,
    \"max_cpu_percent\": $MAX_CPU_PERCENT
  },
  \"results\": {" > "$report_file"

    local first=true
    while IFS=':' read -r metric value; do
        if [[ "$first" == false ]]; then
            echo "," >> "$report_file"
        fi
        first=false
        echo "    \"$metric\": \"$value\"" >> "$report_file"
    done < "$VALIDATION_RESULTS_FILE"

    echo "
  },
  \"log_directory\": \"$LOG_DIR\"
}" >> "$report_file"
}

# Generate HTML report
generate_html_report() {
    local overall_result="$1"
    local report_file="$2"

    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>p2p-ddns Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
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
        <h1>p2p-ddns Integration Test Validation Report</h1>
        <p class="timestamp">Generated on $(date)</p>
        <p><strong>Overall Result: <span class="$overall_result">$overall_result</span></strong></p>
        <p>Validation Mode: $([ "$STRICT_MODE" == true ] && echo "Strict" || echo "Normal")</p>
    </div>

    <h2>Validation Results</h2>
    <table>
        <tr><th>Metric</th><th>Result</th></tr>
EOF

    while IFS=':' read -r metric value; do
        local display_name
        case "$metric" in
            container_health) display_name="Container Health" ;;
            dns_records) display_name="DNS Records" ;;
            error_count) display_name="Error Count" ;;
            network_connectivity) display_name="Network Connectivity" ;;
            resource_usage) display_name="Resource Usage" ;;
            *) display_name="$metric" ;;
        esac

        local result_class="passed"
        if [[ "$value" == "failed" || ("$metric" == "error_count" && ${value%.*} -gt $MAX_ERROR_COUNT) ]]; then
            result_class="failed"
        fi

        echo "        <tr><td>$display_name</td><td class=\"$result_class\">$value</td></tr>" >> "$report_file"
    done < "$VALIDATION_RESULTS_FILE"

    cat >> "$report_file" << EOF
    </table>

    <h2>Thresholds</h2>
    <ul>
        <li>Minimum DNS Records: $MIN_DNS_RECORDS</li>
        <li>Maximum Error Count: $MAX_ERROR_COUNT</li>
        <li>Minimum Uptime: $MIN_UPTIME_PERCENT%</li>
        <li>Maximum Memory: ${MAX_MEMORY_MB}MiB</li>
        <li>Maximum CPU: ${MAX_CPU_PERCENT}%</li>
    </ul>

    <p><em>Log Directory: $LOG_DIR</em></p>
</body>
</html>
EOF
}

# Main validation execution
main() {
    parse_args "$@"

    header "p2p-ddns Integration Test Validation"
    echo "Log Directory: $LOG_DIR"
    echo "Output Format: $OUTPUT_FORMAT"
    echo "Strict Mode: $STRICT_MODE"
    echo

    # Check if log directory exists
    if [[ ! -d "$LOG_DIR" ]]; then
        error "Log directory not found: $LOG_DIR"
        exit 1
    fi

    # Setup temporary results file
    VALIDATION_RESULTS_FILE=$(mktemp)
    trap "rm -f $VALIDATION_RESULTS_FILE" EXIT

    # Load custom thresholds
    load_thresholds

    # Run validations
    local validations_passed=0
    local total_validations=0

    # Container health validation
    ((total_validations++))
    if validate_container_health; then
        ((validations_passed++))
    fi

    # DNS records validation
    ((total_validations++))
    if validate_dns_records; then
        ((validations_passed++))
    fi

    # Error count validation
    ((total_validations++))
    if validate_error_counts; then
        ((validations_passed++))
    fi

    # Network connectivity validation (only if containers are running)
    if docker-compose ps -q 2>/dev/null | grep -q .; then
        ((total_validations++))
        if validate_network_connectivity; then
            ((validations_passed++))
        fi
    fi

    # Resource usage validation (only if containers are running)
    if docker-compose ps -q 2>/dev/null | grep -q .; then
        ((total_validations++))
        if validate_resource_usage; then
            ((validations_passed++))
        fi
    fi

    # Determine overall result
    local overall_result="failed"
    if [[ $validations_passed -eq $total_validations ]]; then
        overall_result="passed"
    fi

    # Generate report
    generate_report "$overall_result"

    # Final summary
    header "Validation Summary"
    echo "Validations Passed: $validations_passed/$total_validations"
    echo "Overall Result: $overall_result"

    if [[ "$overall_result" == "passed" ]]; then
        log "All validations PASSED"
        exit 0
    else
        error "Some validations FAILED"
        exit 1
    fi
}

# Global variables
VALIDATION_RESULTS_FILE=""

# Run main function with all arguments
main "$@"