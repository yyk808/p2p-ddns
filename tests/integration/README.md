# p2p-ddns Integration Tests (Docker)

This directory contains Docker-based integration tests for validating p2p-ddns behavior under
multiple network topologies (multi-subnet, partitions, multi-homed nodes).

The current runner is **matrix-based**: each case generates its own docker compose file and its own
isolated Docker networks, then cleans up automatically.

## Quick Start

From the repository root:

```bash
./test-integration.sh full
./test-integration.sh quick
./test-integration.sh scenario network-topology
./test-integration.sh clean
```

From this directory:

```bash
./single-machine-test.sh full
./single-machine-test.sh scenario fault-recovery
./quick-test.sh clean
```

## Runner Scripts

- `scripts/p2p-matrix.sh`: topology + scale matrix runner (recommended)
- `scripts/test-scenarios.sh`: maps scenarios to matrix cases
- `scripts/build-images-simple.sh`: builds test images (BuildKit + cache mounts)

## Debugging Failures

- Use `scripts/p2p-matrix.sh --keep` to keep containers/networks on failure and print the compose
  project name + compose file path for manual inspection.
- Inspect per-node logs inside the containers under `/app/logs/`.

See `TROUBLESHOOTING.md` for common Docker/OrbStack issues and cleanup tips.
