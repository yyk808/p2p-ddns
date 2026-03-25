# p2p-ddns

A peer-to-peer node directory and address synchronization daemon for unstable or segmented networks.

## What It Is

`p2p-ddns` helps a group of machines learn and keep track of each other's current addresses when:

- hosts frequently change IPs because of DHCP
- the network is split across multiple broadcast domains
- you do not want to depend on a central coordination service

Today, the project's core function is P2P membership and address synchronization. It maintains a
shared view of known nodes and exposes that state through local management APIs.

## What It Is Not

- Not a proxy service
- Not a NAT traversal product by itself
- Not a full DNS server today

There is a reusable hosts-file helper in the codebase, but the daemon does not currently wire node
state into `/etc/hosts` or a DNS responder automatically.

## Features

- P2P node discovery and record synchronization over QUIC
- Offline-first operation on LANs via mDNS and static bootstrap tickets
- Optional relay / DHT support for harder network topologies
- Embedded persistence with `redb`
- Local management over Unix socket, plus optional HTTP admin endpoint
- Pure Rust implementation for cross-platform deployment

## Architecture

- `daemon` mode runs the P2P node plus management servers
- `client` mode talks to a running daemon over the local admin API
- `Ticket` values act as bootstrap credentials for joining an existing network
- Node state is synchronized with `iroh-gossip` broadcasts plus direct point-to-point messages

## Build

```bash
cargo build
```

## Usage

### Start a new network

```bash
cargo run -- --daemon --primary --domain mynode
```

### Join an existing network

```bash
cargo run -- --daemon --ticket <TICKET_STRING> --domain mynode
```

### Query a running daemon from the local machine

```bash
cargo run -- --client --ticket <TICKET_STRING> status
cargo run -- --client --ticket <TICKET_STRING> list
cargo run -- --client --ticket <TICKET_STRING> get-ticket
```

### Useful daemon options

- `--bind <ADDR>`: bind the P2P endpoint to a specific address
- `--config <DIR>`: set the storage directory
- `--no-mdns`: disable local-network discovery
- `--dht`: enable PKARR/DHT discovery when built with `--features pkarr-dht`
- `--admin-http <ADDR>`: expose the admin API over HTTP
- `--relay-mode <disabled|default|staging>`: configure relay usage
- `--relay-url <URL>`: use one or more self-hosted relays
- `--reset-storage`: intentionally wipe persisted node/topic/ticket state before startup

### Example admin flow

1. Start a primary daemon.
2. Fetch its ticket with `get-ticket`.
3. Start other daemons with that ticket.
4. Use `list` or `status` from `client` mode to inspect the network.

## Testing

Run the default test suite:

```bash
cargo test
```

Docker-backed topology tests are available separately and auto-skip when Docker is unavailable:

```bash
cargo test --test docker_p2p -- --nocapture
```

See [tests/integration/README.md](tests/integration/README.md) for the Docker topology matrix.

## Tech Stack

- Runtime: `tokio`
- Networking: `iroh`, `iroh-gossip`
- Storage: `redb`
- Serialization: `postcard`
- CLI: `clap`

## License

This project is licensed under the MIT License. See [LICENCE](LICENCE).
