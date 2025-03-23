# p2p-ddns2

A peer-to-peer Dynamic DNS (DDNS) service project.

## What is this for?
Managing numerous network devices that lack GUIs can be challenging as they can only be accessed remotely (e.g., via SSH). In large public networks (such as campus networks) with DHCP enabled, devices may receive different IP addresses upon reconnection. Moreover, these networks often use multi-layered, tree-structured architectures with extensive router-isolated broadcast domains, making simple multicast-based device discovery unfeasible.

This project addresses these challenges by providing a robust DDNS solution.

## What is this NOT for?
- Proxy service
- NAT traversal

## Features
- Peer-to-peer network for DDNS record synchronization.
- Pure Rust implementation, easy cross platform deployment.
- Using QUIC protocol for secure and fast communication.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yyk808/p2p-ddns.git
   ```
2. Navigate to the project directory:
   ```bash
   cd p2p-ddns
   ```
3. Build:
   ```bash
   cargo build
   ```

## Key Concepts
- Peer-to-peer communication enables direct record synchronization among devices.
- The project leverages QUIC protocol for secure and fast communication.
- Pure Rust implementation ensures easy cross-platform deployment and robust performance.

## Usage
### Running Modes
The project supports two running modes:
- Daemon mode: In this mode the program will publish its own domain name and synchronize information with other nodes. Use the "--daemon" flag along with options like "--alias" to set the node name and optionally "--primary" if it is the first node. For example:
   ```bash
   ./p2p-ddns2 --daemon --alias mynode --primary
   ```
   You can also use the "--ticket" option to join an existing network:
   ```bash
   ./p2p-ddns2 --daemon --ticket <TICKET_STRING> --alias mynode
   ```
- Client mode: In this mode the program only synchronizes information from daemon nodes and does not publish its own domain name. For example:
   ```bash
   ./p2p-ddns2 --ticket <TICKET_STRING>
   ```

Additional options such as "--bind" for specifying the bind address and "--config" for a custom configuration path are available.

```log
Usage: p2p-ddns [OPTIONS]

Options:
  -d, --daemon                Running mode, daemon or client(default)
      --primary               To be the first node in this p2p network
  -a, --alias <NICKNAME>      Name of this node, used in dns resolving
  -t, --ticket <TICKET>       Use ticket string to join a existing network
  -c, --config <CONFIG_PATH>  Manually specify the path of the database file
  -L, --log <LOG>             Log level, default is info [default: info] [possible values: trace, debug, info, warn, error, off]
  -B, --bind <BIND_ADDR>
      --debug                 For debug convinience
  -h, --help                  Print help
  -V, --version               Print version
```

## License
This project is licensed under the MIT License. Please refer to the [LICENCE](LICENCE) file for details.

## Maintainers
This project is developed and maintained by Neon.
