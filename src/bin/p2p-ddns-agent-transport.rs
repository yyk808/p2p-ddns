use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::Result;
use clap::{Parser, builder::TypedValueParser};
use p2p_ddns::{
    agent_transport::{AdminClient, AdminEndpoint, TransportConfig, run_transport},
    app::init_logging,
    cli::args::LogLevel,
};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "p2p-ddns-agent-transport",
    version,
    about = "Direct LAN message transport backed by p2p-ddns discovery",
    long_about = None
)]
struct Args {
    /// HTTP bind address for /send, /inbox, /events, and /health.
    #[arg(long, default_value = "0.0.0.0:39091")]
    bind: SocketAddr,

    /// Port peers should use when dialing this transport. Defaults to --bind port.
    #[arg(long)]
    advertise_port: Option<u16>,

    /// Local sender id included in outbound messages.
    #[arg(long, default_value = "agent")]
    local_id: String,

    /// Path to p2p-ddns daemon's Unix admin socket.
    #[arg(long, value_name = "SOCKET_PATH", conflicts_with = "admin_http")]
    socket_path: Option<PathBuf>,

    /// Connect to p2p-ddns daemon over admin HTTP instead of the local socket.
    #[arg(long, value_name = "ADMIN_HTTP", conflicts_with = "socket_path")]
    admin_http: Option<SocketAddr>,

    /// Optional p2p-ddns admin ticket, required for non-loopback admin HTTP.
    #[arg(short, long, value_name = "TICKET")]
    ticket: Option<String>,

    /// Optional shared secret required for remote /inbox and non-loopback /send.
    #[arg(long, value_name = "SECRET")]
    shared_secret: Option<String>,

    /// p2p-ddns admin command timeout in seconds.
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    /// Log level.
    #[arg(
        long,
        short = 'L',
        default_value_t = LogLevel::Info,
        value_parser = clap::builder::PossibleValuesParser::new(["trace", "debug", "info", "warn", "error", "off"])
            .map(|s: String| s.parse::<LogLevel>().unwrap()),
    )]
    log: LogLevel,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(args.log);

    let admin_endpoint = match args.admin_http {
        Some(bind) => AdminEndpoint::Http(bind),
        None => AdminEndpoint::UnixSocket(
            args.socket_path
                .unwrap_or_else(p2p_ddns::admin::server::default_socket_path),
        ),
    };
    let admin = AdminClient::new(
        admin_endpoint,
        Duration::from_secs(args.timeout),
        args.ticket,
    );
    let config = TransportConfig {
        bind: args.bind,
        advertise_port: args.advertise_port.unwrap_or(args.bind.port()),
        local_id: args.local_id,
        admin,
        shared_secret: args.shared_secret,
    };
    run_transport(config).await
}
