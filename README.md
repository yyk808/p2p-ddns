# p2p-ddns

A peer-to-peer DDNS daemon for unstable or segmented networks.

## What It Is

`p2p-ddns` helps a group of machines learn and keep track of each other's current addresses when:

- hosts frequently change IPs because of DHCP
- the network is split across multiple broadcast domains
- you do not want to depend on a central coordination service

`p2p-ddns` maintains a shared view of node names and current addresses, then can project that view
into the local machine's hosts file. In practice, it gives you an application-level DDNS path:

- nodes announce a name and join a P2P network
- the network synchronizes current addresses
- each daemon can write resolved records into `/etc/hosts`
- local tools such as `ssh`, `ping`, and `curl` can then resolve those names normally

## What It Is Not

- Not a proxy service
- Not a NAT traversal product by itself
- Not a full DNS server today
- Not a recursive resolver
- Not a replacement for an authoritative DNS service

The current DDNS integration path is hosts-file synchronization, not a standalone DNS protocol
server.

## Features

- P2P node discovery and record synchronization over QUIC
- Offline-first operation on LANs via mDNS and static bootstrap tickets
- Optional relay / DHT support for harder network topologies
- Optional hosts-file synchronization for local name resolution
- Embedded persistence with `redb`
- Local management over Unix socket, plus optional HTTP admin endpoint
- Pure Rust implementation for cross-platform deployment

## Architecture

- `daemon` mode runs the P2P node plus management servers
- `client` mode talks to a running daemon over the local admin API
- `Ticket` values act as bootstrap credentials for joining an existing network
- Node state is synchronized with `iroh-gossip` broadcasts plus direct point-to-point messages
- DDNS is implemented at the application layer by translating synchronized node records into hosts
  file entries

## Build

```bash
cargo build
```

## Release Artifacts

GitHub Releases publish the following artifacts automatically when a new tag such as `v0.2.0` is
pushed:

- Linux `x86_64` and `aarch64` `.tar.gz` archives
- Linux `x86_64` and `aarch64` `.deb` packages
- macOS `x86_64` and `aarch64` `.tar.gz` archives
- `SHA256SUMS.txt` for artifact verification

Current release automation does not publish Windows builds yet because the local admin client/server
still uses Unix domain sockets.

## Usage

Installed binaries:

- `p2p-ddns`: daemon/node process
- `p2p-ddnsctl`: local management client

### Start a new network

```bash
cargo run --bin p2p-ddns -- --primary --domain mynode
```

The primary daemon prints `Ticket (raw): <TICKET_STRING>` on startup. Copy that value and use it
to join other daemons.

### Join an existing network

```bash
cargo run --bin p2p-ddns -- --ticket <TICKET_STRING> --domain mynode
```

### Bind to a specific IP or interface

Bind to a specific IP while reusing the daemon's persisted port:

```bash
cargo run --bin p2p-ddns -- --primary --domain mynode --bind 192.168.1.10
```

Bind to a specific IP and port:

```bash
cargo run --bin p2p-ddns -- --primary --domain mynode --bind 192.168.1.10:7777
```

Bind using the first IPv4/IPv6 address found on a named network interface:

```bash
cargo run --bin p2p-ddns -- --primary --domain mynode --bind-interface eth0
```

Notes:

- `--bind` accepts either `IP` or `IP:PORT`
- `--bind-interface` selects addresses from a named interface and reuses the persisted bind port
- `--bind` and `--bind-interface` are mutually exclusive
- If no bind port has been persisted yet, one is generated and stored automatically
- Interface matching accepts the OS interface name, and on Windows also accepts the friendly name

### Query a running daemon from the local machine

`client` mode talks to the local daemon over a Unix socket and does not require a ticket by
default. A ticket is still required when adding other daemons to the network or when using the
optional HTTP admin endpoint.

```bash
cargo run --bin p2p-ddnsctl -- status
cargo run --bin p2p-ddnsctl -- list
cargo run --bin p2p-ddnsctl -- get-ticket
```

### Enable hosts-based DDNS

To write synchronized records into the system hosts file:

```bash
sudo cargo run --bin p2p-ddns -- --primary --domain mynode --hosts-sync
```

To also publish a suffix form such as `mynode.p2p`:

```bash
sudo cargo run --bin p2p-ddns -- --ticket <TICKET_STRING> --domain mynode --hosts-sync --hosts-suffix p2p
```

To test safely without touching `/etc/hosts`, point hosts sync at a temporary file:

```bash
cargo run --bin p2p-ddns -- --primary --domain mynode --hosts-sync --hosts-path /tmp/p2p-ddns.hosts
```

### Useful daemon options

- `--bind <ADDR>`: bind the P2P endpoint to a specific IP or `IP:PORT`
- `--bind-interface <INTERFACE>`: bind using the first IPv4/IPv6 address found on a named interface
- `--config <DIR>`: set the storage directory
- `--no-mdns`: disable local-network discovery
- `--dht`: enable PKARR/DHT discovery when built with `--features pkarr-dht`
- `--admin-http <ADDR>`: expose the admin API over HTTP
- `--hosts-sync`: write synchronized node records into a hosts file section
- `--hosts-path <FILE>`: override the hosts file path used by `--hosts-sync`
- `--hosts-suffix <SUFFIX>`: also write suffixed names such as `node.<SUFFIX>`
- `--relay-mode <disabled|default|staging>`: configure relay usage
- `--relay-url <URL>`: use one or more self-hosted relays
- `--reset-storage`: intentionally wipe persisted node/topic/ticket state before startup

### Example admin flow

1. Start a primary daemon.
2. Copy the `Ticket (raw)` value printed by the primary daemon at startup.
3. Start other daemons with that ticket.
4. Use `list` or `status` from `client` mode to inspect the network.
5. Use `get-ticket` later if you want to re-save or re-share the current network ticket.

### Example DDNS Flow

1. Start a primary daemon with `--hosts-sync`.
2. Copy the `Ticket (raw)` value printed by the primary daemon at startup.
3. Start other daemons with the same ticket and `--hosts-sync`.
4. Wait for membership to converge.
5. Resolve peer names locally through the managed `p2p-ddns` section in the hosts file.

## Hosts Sync Notes

- `--hosts-sync` writes only the `p2p-ddns` managed section and leaves the rest of the hosts file
  untouched.
- Writes require permission to modify the target hosts file. On Unix that usually means root, or a
  system service user with sufficient privileges.
- Invalid hostnames are skipped rather than written.
- Client-only admin sessions are not written into hosts records.
- The current design chooses one best IP per node for the local machine rather than writing every
  observed address.

## Systemd Deployment

The repository includes Debian/systemd packaging assets under
[`packaging/systemd`](packaging/systemd).

The common deployment path is:

1. Build or package the binary.
2. Install the systemd service and wrapper.
3. Edit `/etc/default/p2p-ddns`.
4. Set `P2P_DDNS_ROLE=primary` or `daemon`.
5. Optionally enable hosts sync with:
   `P2P_DDNS_HOSTS_SYNC=1`
   `P2P_DDNS_HOSTS_SUFFIX=p2p`
   For bind-related settings:
   `P2P_DDNS_BIND_ADDRESS=192.168.1.10`
   or `P2P_DDNS_EXTRA_ARGS="--bind-interface eth0"`
6. Start the service with `systemctl enable --now p2p-ddns`.

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
