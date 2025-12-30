# p2p-ddns Integration Test Framework Usage Guide

This guide explains how to use the comprehensive Docker-based integration test framework for the p2p-ddns project.

## Quick Start

### 1. Basic Usage

```bash
# Navigate to integration test directory
cd tests/integration

# Run a quick smoke test
./quick-test.sh quick

# Run full test suite
./quick-test.sh full

# Run specific test scenarios
./quick-test.sh basic     # Basic functionality
./quick-test.sh network   # Network topology
./quick-test.sh fault     # Fault recovery
```

### 2. Advanced Usage

```bash
# Run with debug logging
./quick-test.sh quick --debug

# Run with custom timeout
./quick-test.sh full --timeout 1800

# Keep containers running after test
./quick-test.sh basic --keep-running

# Skip building images
./quick-test.sh quick --no-build
```

## Architecture Overview

### Network Topology

The test environment simulates a realistic multi-subnet network:

```
┌─────────────────────────────────────────────────┐
│                Docker Host                       │
├─────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐            │
│  │ Subnet A     │  │ Subnet B     │            │
│  │ 10.0.1.0/24  │  │ 10.0.2.0/24  │            │
│  │              │  │              │            │
│  │ primary-node │  │ daemon-b1    │            │
│  │ daemon-a1    │  │ daemon-b2    │            │
│  │ daemon-a2    │  │ client-b1    │            │
│  │ client-a1    │  │              │            │
│  └──────────────┘  └──────────────┘            │
│                                                 │
│  ┌──────────────┐                              │
│  │ Public Net   │                              │
│  │ 10.0.0.0/24  │                              │
│  │              │                              │
│  │ monitor      │                              │
│  └──────────────┘                              │
└─────────────────────────────────────────────────┘
```

### Node Types

- **Primary Node**: Network creator, generates initial tickets
- **Daemon Nodes**: Publish DNS information, participate in synchronization
- **Client Nodes**: Only synchronize data, don't publish information
- **Monitor Node**: Observes and reports on test execution

## Test Scenarios

### 1. Basic Functionality
- ✅ Primary node startup and ticket generation
- ✅ Daemon nodes joining via tickets
- ✅ Client nodes joining and data synchronization
- ✅ DNS record propagation

### 2. Network Topology
- ✅ Cross-subnet communication
- ✅ Network discovery mechanisms
- ✅ Route discovery and verification
- ✅ Gossip protocol message propagation

### 3. Fault Recovery
- ✅ Daemon node failure and recovery
- ✅ Network partition simulation
- ✅ Primary node isolation testing
- ✅ System recovery verification

### 4. Performance Stress
- ✅ High load testing
- ✅ Concurrent operations
- ✅ Resource usage monitoring
- ✅ System stability verification

## Manual Testing

### Starting the Environment

```bash
# Build images and start containers
./quick-test.sh build
./quick-test.sh start

# Check status
./quick-test.sh status

# View logs
./quick-test.sh logs
```

### Network Manipulation

```bash
# Isolate a network subnet
./networks/network-control.sh isolate-network subnet-a

# Isolate a specific container
./networks/network-control.sh isolate-container primary-node

# Block specific connections
./networks/network-control.sh block-connection daemon-a1 daemon-b1

# Restore connectivity
./networks/network-control.sh restore-network subnet-a
./networks/network-control.sh restore-container primary-node
```

### Monitoring and Debugging

```bash
# View real-time logs
docker-compose logs -f

# Check specific container logs
docker-compose logs primary-node
docker-compose logs daemon-a1

# Execute commands in containers
docker-compose exec primary-node /bin/bash
docker-compose exec daemon-a1 ping primary-node

# Monitor resource usage
docker stats
```

## Configuration

### Environment Variables

Key environment variables that can be customized:

```bash
# General settings
P2P_DDNS_LOG_LEVEL=info|debug|warn|error
P2P_DDNS_MODE=daemon|client
P2P_DDNS_PRIMARY=true|false

# Network settings
P2P_DDNS_BIND_ADDRESS=0.0.0.0:8080
P2P_DDNS_DOMAIN=my-node

# Test settings
TICKET_WAIT_TIMEOUT=120
HEALTH_CHECK_INTERVAL=30
DNS_MONITOR_INTERVAL=45
```

### Validation Thresholds

Default validation thresholds (can be customized):

```bash
MIN_DNS_RECORDS=3
MAX_ERROR_COUNT=5
MIN_UPTIME_PERCENT=90
MAX_MEMORY_MB=512
MAX_CPU_PERCENT=80
```

## Test Reports

### Generating Reports

```bash
# Validate test results
./scripts/validate.sh

# Generate JSON report
./scripts/validate.sh --output json

# Generate HTML report
./scripts/validate.sh --output html

# Strict validation mode
./scripts/validate.sh --strict
```

### Report Locations

- **Logs**: `./logs/` - Container logs and test execution logs
- **Reports**: `./reports/` - Validation reports and test summaries
- **Data**: `./volumes/` - Persistent data for containers

## Troubleshooting

### Common Issues

1. **Container startup failures**
   ```bash
   # Check container logs
   docker-compose logs primary-node

   # Verify network connectivity
   docker network ls
   ```

2. **Ticket generation failures**
   ```bash
   # Check primary node logs
   docker-compose logs primary-node | grep -i ticket

   # Verify file permissions
   docker-compose exec primary-node ls -la /app/
   ```

3. **Network connectivity issues**
   ```bash
   # Test basic connectivity
   docker-compose exec daemon-a1 ping primary-node

   # Check network configuration
   docker-compose exec daemon-a1 ip route show
   ```

4. **High resource usage**
   ```bash
   # Monitor resource usage
   docker stats

   # Check for memory leaks
   docker-compose exec primary-node ps aux
   ```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# Run tests with debug logging
./quick-test.sh quick --debug

# Enable debug in specific containers
P2P_DDNS_LOG_LEVEL=debug ./quick-test.sh start
```

### Cleanup

If tests fail or environment gets corrupted:

```bash
# Complete cleanup
./quick-test.sh clean

# Force cleanup
./networks/cleanup-networks.sh force

# Remove all test data
docker system prune -f
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2

    - name: Run Integration Tests
      run: |
        cd tests/integration
        ./quick-test.sh full --timeout 1800

    - name: Upload Test Reports
      uses: actions/upload-artifact@v2
      if: always()
      with:
        name: test-reports
        path: tests/integration/reports/
```

### Local CI Script

```bash
#!/bin/bash
# ci-test.sh

set -euo pipefail

echo "Running CI integration tests..."

cd tests/integration

# Build images
./quick-test.sh build

# Run full test suite
if ./quick-test.sh full --timeout 1800; then
    echo "✅ All tests passed"

    # Generate reports
    ./scripts/validate.sh --output json
    ./scripts/validate.sh --output html

    # Clean up
    ./quick-test.sh clean

    exit 0
else
    echo "❌ Tests failed"

    # Keep environment for debugging
    ./quick-test.sh status

    exit 1
fi
```

## Advanced Features

### Custom Test Scenarios

Create custom test scenarios by extending `scripts/test-scenarios.sh`:

```bash
run_custom_scenario() {
    header "Custom Test Scenario"

    # Custom test logic here

    log "Custom scenario passed"
    return 0
}
```

### Network Simulation

Use the network control script for advanced network testing:

```bash
# Simulate network partition
./networks/network-control.sh isolate-network subnet-a
sleep 30
./networks/network-control.sh restore-network subnet-a

# Simulate packet loss (requires tc)
docker-compose exec daemon-a1 tc qdisc add dev eth0 root netem loss 10%
```

### Performance Monitoring

Monitor test performance with custom metrics:

```bash
# Monitor DNS resolution time
time docker-compose exec client-a1 ping primary-node

# Monitor message propagation
docker-compose logs daemon-a1 | grep "Received message"
```

## Contributing

When adding new test scenarios:

1. Update `scripts/test-scenarios.sh` with new scenario
2. Add appropriate validation checks
3. Update documentation
4. Test on multiple platforms
5. Add to CI pipeline

For questions or issues, please refer to the main project documentation or create an issue in the repository.