# AGENTS.md

This file contains guidelines for agentic coding agents working on the p2p-ddns project.

## Build, Lint, and Test Commands

### Building
```bash
cargo build                    # Debug build
cargo build --release          # Optimized release build
cargo check                    # Quick syntax/type check
```

### Testing
```bash
cargo test                     # Run all tests
cargo test <test_name>         # Run a specific test
cargo test <module>::<test>    # Run test in specific module
cargo test -- --nocapture      # Show print output
```

Running a single test:
```bash
cargo test test_node_storage
cargo test protocol::test_p2p_protocol
```

### Linting and Formatting
```bash
cargo fmt                      # Format code
cargo clippy                   # Run linter (use -D warnings for CI)
cargo doc --no-deps            # Generate documentation
```

### Integration Tests
```bash
# Docker-based P2P tests (testcontainers-rs)
P2P_DDNS_IT=1 cargo test --test docker_p2p -- docker_p2p_smoke
P2P_DDNS_IT_MATRIX=1 cargo test --test docker_p2p
P2P_DDNS_IT_NEGATIVE=1 cargo test --test docker_p2p -- docker_p2p_expected_failures

# Useful toggles
P2P_DDNS_IT_SUBNETS=2 P2P_DDNS_IT_DAEMONS=10 P2P_DDNS_IT=1 cargo test --test docker_p2p -- docker_p2p_smoke
P2P_DDNS_IT_NO_BUILD=1 P2P_DDNS_IT=1 cargo test --test docker_p2p -- docker_p2p_smoke
P2P_DDNS_IT_KEEP_DOCKER=1 P2P_DDNS_IT=1 cargo test --test docker_p2p -- docker_p2p_smoke -- --nocapture
P2P_DDNS_IT_CASE=partition-recover P2P_DDNS_IT_MATRIX=1 cargo test --test docker_p2p -- docker_p2p_matrix
```

## Code Style Guidelines

### Imports
- Group imports: std library first, then external crates, then local crate
- Use `use crate::` for local module imports
- Keep imports sorted alphabetically within each group

```rust
use std::{collections::BTreeMap, net::SocketAddr};
use anyhow::Result;
use iroh::{Endpoint, NodeId};
use crate::{network::Context, storage::Storage};
```

### Naming Conventions
- **Types**: PascalCase (structs, enums, type aliases)
- **Functions/Methods**: snake_case
- **Constants**: SCREAMING_SNAKE_CASE
- **Private fields**: snake_case
- **Public fields**: snake_case (when visible)

### Error Handling
- Use `anyhow::Result<T>` for function return types
- Use `anyhow::bail!()` or `anyhow::anyhow!()` for errors
- Prefer `?` operator for error propagation
- Use `log::error!()` for logging errors

```rust
use anyhow::Result;

pub fn do_something() -> Result<()> {
    let value = get_value()?;
    if value.is_none() {
        anyhow::bail!("Value is required");
    }
    Ok(())
}
```

### Async Code
- Use `async fn` for async functions
- Use `#[compio::main]` or `#[compio::test]` for entry points
- Always use `.await` (not `block_on`)
- Use compio's async types (futures::channel, compio::runtime::time)

### Visibility and Structure
- Mark items `pub` only when needed for external access
- Use `pub(crate)` for items visible within the crate
- Group related functions in `impl` blocks
- Use `#[cfg(test)]` modules for unit tests

### Data Serialization
- Use `serde::{Serialize, Deserialize}` for serializable types
- Use `postcard` for binary serialization (this project's choice)
- Use `postcard::to_stdvec()` and `postcard::from_bytes()`

### Type Traits
- Implement `Debug` for all public types
- Implement `Clone` for types that need to be cloned frequently
- Implement `Display` for user-facing string representations
- Implement `Hash`/`Eq` for types used as map keys

### Concurrency
- Use `Arc<T>` for shared ownership across threads
- Use `RwLock<T>` (parking_lot) for read-write locks
- Use `DashMap<K, V>` for concurrent hash maps
- Use `futures::channel::mpsc` for async channels

### Logging
- Use `log::info!()` for informational messages
- Use `log::debug!()` for development debugging
- Use `log::warn!()` for warnings
- Use `log::error!()` for errors
- Never log secrets or sensitive data

### Testing Patterns
- Write unit tests in `#[cfg(test)]` modules within files
- Use `tempfile::tempfile()` for temporary file tests
- Use `#[test]` attribute for sync tests
- Use `#[compio::test]` for async tests
- Comment out broken tests with `// #[test]` rather than removing

### Documentation
- Use `///` for public API documentation
- Provide examples for complex APIs
- Document error conditions in doc comments
- Keep inline comments minimal and focused

## Project-Specific Conventions

- **Runtime**: Uses `compio` async runtime (not tokio)
- **Storage**: Uses `redb` embedded database
- **Networking**: Uses `iroh` P2P networking library
- **CLI**: Uses `clap` with derive features
- **Serialization**: Uses `postcard` (not JSON)
- **Version**: Rust 2024 edition (note: this is very new)

## Cargo.toml Dependencies
Core dependencies to understand before using:
- `iroh` - P2P networking
- `iroh-gossip` - Gossip protocol
- `redb` - Embedded database
- `postcard` - Binary serialization
- `parking_lot` - Fast synchronization primitives
- `compio` - Async runtime

## Before Committing
Always run:
```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```
