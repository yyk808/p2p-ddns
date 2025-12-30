# p2p-ddns Integration Tests

This directory contains integration tests for the p2p-ddns project using Docker to simulate complex network environments.

## Purpose

The integration tests verify the correctness of the p2p-ddns system under various network conditions, simulating real-world deployment scenarios such as:

- Large campus/corporate networks with multiple subnets
- DHCP environments with dynamic IP assignments
- Network partitions and recovery scenarios
- Multi-layered network topologies with router isolation

## Architecture

The test environment consists of:

- **Multiple Docker networks**: Simulating different network segments (subnet-a, subnet-b, public)
- **8 test nodes**: 1 primary + 4 daemons + 2 clients + 1 monitor
- **Network isolation**: Ability to simulate network partitions
- **Comprehensive test scenarios**: Covering various failure and recovery cases

## Usage

### Quick Start

```bash
# Run all integration tests
./scripts/run-tests.sh

# Run specific test scenarios
./scripts/test-scenarios.sh --scenario=basic-functionality

# Clean up test environment
./scripts/cleanup.sh
```

### Manual Testing

```bash
# Create test networks
./networks/create-networks.sh

# Start test environment
docker-compose -f docker-compose.yml up -d

# Monitor test progress
docker-compose -f docker-compose.yml logs -f

# Stop test environment
docker-compose -f docker-compose.yml down
```

## Test Scenarios

1. **Basic Functionality**: Node startup, network joining, data synchronization
2. **Network Topology**: Cross-subnet communication, route discovery
3. **Fault Recovery**: Node failures, network partitions, primary node recovery
4. **Performance Stress**: Large-scale nodes, concurrent operations
5. **Configuration Changes**: Dynamic reconfiguration, version compatibility

## Configuration

Test configurations are stored in the `configs/` directory:
- `primary.toml`: Primary node configuration
- `daemon.toml`: Daemon node configuration
- `client.toml`: Client node configuration

## Reports

Test results and logs are saved to:
- `logs/`: Container logs and test execution logs
- `reports/`: Test reports and performance metrics

## Requirements

- Docker Engine 20.10+
- Docker Compose 2.0+
- Bash shell
- (Optional) Python 3.8+ for advanced reporting tools