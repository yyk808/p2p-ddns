# p2p-ddns Integration Tests (Docker + Rust)

This directory contains the Docker image definitions used by the Rust integration tests in
`tests/docker_p2p.rs` (powered by `testcontainers-rs`).

The tests validate p2p-ddns behavior under multiple network topologies (multi-subnet, partitions,
multi-homed nodes) using Docker network isolation.

## Run (recommended)

Smoke test (single case):

```bash
P2P_DDNS_IT=1 cargo test --test docker_p2p -- docker_p2p_smoke
```

Full matrix (multiple topologies + sizes):

```bash
P2P_DDNS_IT_MATRIX=1 cargo test --test docker_p2p
```

## Useful environment variables

- `P2P_DDNS_IT=1`: enable the smoke Docker integration test
- `P2P_DDNS_IT_MATRIX=1`: enable the full Docker matrix test
- `P2P_DDNS_IT_NO_BUILD=1`: skip building images (assumes images already exist locally)
- `P2P_DDNS_IT_IMAGE_TAG=...`: tag for node images (default: `tc`)
- `P2P_DDNS_IT_KEEP_DOCKER=1`: keep containers + networks for debugging
- `P2P_DDNS_IT_SUBNETS=...`: smoke test subnet count (default: 1)
- `P2P_DDNS_IT_DAEMONS=...`: smoke test daemon count (default: 4)
- `P2P_DDNS_IT_GATEWAY=1`: smoke test includes a multi-homed daemon
- `P2P_DDNS_IT_PARTITION_RECOVER=1`: smoke test includes disconnect/reconnect of primary
- `P2P_DDNS_IT_CASE=...`: run a single matrix case by name
- `P2P_DDNS_IT_MATRIX_DYNAMIC=1`: generate cases from env (instead of built-in cases)
- `P2P_DDNS_IT_MATRIX_SUBNETS=1,2,3`: dynamic matrix subnet counts
- `P2P_DDNS_IT_MATRIX_DAEMONS=2,4,8`: dynamic matrix daemon counts
- `P2P_DDNS_IT_MATRIX_GATEWAY=1`: dynamic matrix includes gateway variants
- `P2P_DDNS_IT_MATRIX_PARTITION_RECOVER=1`: dynamic matrix includes partition/recover variants

See `TROUBLESHOOTING.md` for common Docker/OrbStack issues and cleanup tips.
