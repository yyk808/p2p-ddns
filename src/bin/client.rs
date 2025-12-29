use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use p2p_ddns::{
    client_daemon_protocol::*,
    types::{ClientInfo, ClientPermissions, DaemonStatus, Node},
    storage::init_storage,
    utils::time_now,
};
use std::env;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "p2p-ddns-client")]
#[command(about = "P2P DDNS Client - Control daemon", long_about = None)]
struct ClientArgs {
    /// Path to daemon's Unix socket
    #[arg(short, long, value_name = "SOCKET_PATH")]
    socket_path: Option<PathBuf>,

    /// P2P ticket (for authentication)
    #[arg(short, long, value_name = "TICKET")]
    ticket: Option<String>,

    /// Request timeout in seconds
    #[arg(short, long, default_value = "5")]
    timeout: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all network nodes
    List,

    /// Get daemon status
    Status,

    /// Add a node using ticket
    AddNode { ticket: String },

    /// Remove a node by ID
    RemoveNode { id: String },

    /// Get current P2P ticket from daemon
    GetTicket,

    /// Pause daemon (future)
    Pause,

    /// Resume daemon (future)
    Resume,

    /// Gracefully shutdown daemon
    Stop,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();

    let ticket = get_ticket()?;

    let socket_path = get_socket_path(&args.socket_path);

    let mut stream = connect_to_daemon(&socket_path, args.timeout).await?;

    let _client_pk = authenticate(&mut stream, &ticket).await?;

    execute_command(&mut stream, args.command).await?;

    Ok(())
}

fn get_ticket() -> Result<String> {
    if let Ok(ticket) = env::var("P2P_DDNS_CLI_ARGS") {
        let args: Vec<String> = ticket.split_whitespace().map(|s| s.to_string()).collect();
        for (i, arg) in args.iter().enumerate() {
            if arg == "--ticket" || arg == "-t" {
                if let Some(ticket) = args.get(i + 1) {
                    return Ok(ticket.clone());
                }
            }
        }
    }

    if let Ok(ticket) = env::var("P2P_DDNS_TICKET") {
        return Ok(ticket);
    }

    let ticket_path = get_client_config_path().join("ticket.txt");
    if ticket_path.exists() {
        let ticket = std::fs::read_to_string(&ticket_path)?;
        return Ok(ticket.trim().to_string());
    }

    Err(anyhow::anyhow!(
        "No ticket found. Please provide via --ticket, P2P_DDNS_TICKET env, or save ticket with 'p2p-ddns-client save-ticket <TICKET>'"
    ))
}

fn get_socket_path(override_path: &Option<PathBuf>) -> PathBuf {
    if let Some(path) = override_path {
        return path.clone();
    }

    if let Ok(path) = env::var("P2P_DDNS_SOCKET") {
        return PathBuf::from(path);
    }

    let candidates = vec![
        env::var("XDG_RUNTIME_DIR").ok()
            .map(|p| PathBuf::from(p).join("p2p-ddns.sock")),
        env::var("RUNTIME_DIR").ok()
            .map(|p| PathBuf::from(p).join("p2p-ddns.sock")),
        Some(PathBuf::from("/run/p2p-ddns.sock")),
        Some(PathBuf::from("/var/run/p2p-ddns.sock")),
    ];

    for candidate in candidates {
        if let Some(path) = candidate {
            if path.exists() {
                return path;
            }
        }
    }

    env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(|p| PathBuf::from(p).join("p2p-ddns.sock"))
        .unwrap_or_else(|| PathBuf::from("/run/p2p-ddns.sock"))
}

async fn connect_to_daemon(
    socket_path: &PathBuf,
    timeout_sec: u64,
) -> Result<tokio::net::UnixStream> {
    let timeout = tokio::time::Duration::from_secs(timeout_sec);

    tokio::time::timeout(timeout, tokio::net::UnixStream::connect(socket_path))
        .await
        .map_err(|_| anyhow::anyhow!(
            "Failed to connect to daemon at {} (timeout: {}s). Is daemon running?",
            socket_path.display(),
            timeout_sec
        ))?
}

async fn authenticate(
    stream: &mut tokio::net::UnixStream,
    ticket: &str,
) -> Result<iroh::PublicKey> {
    let storage = init_client_storage().await?;
    let (pk, _sk) = storage.load_secret()?.unwrap_or_else(|| {
        let mut rng = rand::rng();
        let sk = iroh::SecretKey::generate(&mut rng);
        let pk = sk.public();
        storage.save_secret(sk).ok();
        (pk, sk)
    });

    let auth_req = AuthRequest {
        ticket: ticket.to_string(),
        client_public_key: Some(
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD_NO_PAD,
                pk.as_bytes()
            )
        ),
        client_name: Some("cli".to_string()),
    };
    send_message(stream, &auth_req).await?;

    let auth_resp: AuthResponse = read_message(stream).await?;

    if !auth_resp.success {
        Err(anyhow::anyhow!(
            "Authentication failed: {}",
            auth_resp.error.unwrap_or_else(|| "Unknown error".to_string())
        ))
    } else {
        info!("Authenticated successfully");
        Ok(pk)
    }
}

async fn execute_command(
    stream: &mut tokio::net::UnixStream,
    command: Commands,
) -> Result<()> {
    let cmd = match command {
        Commands::List => ClientCommand::Query,
        Commands::Status => ClientCommand::Status,
        Commands::AddNode { ticket } => ClientCommand::AddNode { ticket },
        Commands::RemoveNode { id } => ClientCommand::RemoveNode { id },
        Commands::GetTicket => ClientCommand::GetTicket,
        Commands::Pause => ClientCommand::Pause,
        Commands::Resume => ClientCommand::Resume,
        Commands::Stop => ClientCommand::Shutdown,
    };

    send_message(stream, &cmd).await?;

    let response: ClientResponse = read_message(stream).await?;

    match response {
        ClientResponse::Nodes(nodes) => {
            display_nodes(&nodes);
        }
        ClientResponse::Status(status) => {
            display_status(&status);
        }
        ClientResponse::Ticket(ticket) => {
            println!("Current P2P Ticket: {}", ticket);

            let ticket_path = get_client_config_path().join("ticket.txt");
            if let Err(e) = std::fs::write(&ticket_path, &ticket) {
                log::warn!("Failed to save ticket: {}", e);
            } else {
                log::info!("Ticket saved to {}", ticket_path.display());
            }
        }
        ClientResponse::Ack => {
            println!("Command executed successfully");
        }
        ClientResponse::Error(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn init_client_storage() -> Result<p2p_ddns::storage::Storage> {
    let config_path = get_client_config_path();
    std::fs::create_dir_all(&config_path)?;

    let db_path = config_path.join("client.db");
    p2p_ddns::storage::Storage::new(db_path)
}

fn get_client_config_path() -> PathBuf {
    dirs::config_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("p2p-ddns")
}

fn display_nodes(nodes: &[Node]) {
    let data = nodes
        .iter()
        .map(|node| {
            let now = time_now();
            let addr = best_ip_for_display(&node.addr)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let alias = node.domain.clone();
            let last_seen = format_duration(now - node.last_heartbeat);
            (addr, alias, last_seen)
        })
        .collect::<Vec<_>>();

    let mut builder = tabled::builder::Builder::default();
    builder.push_record(["Address", "Name", "Last Seen"]);
    for (addr, alias, last_seen) in data {
        builder.push_record([addr, alias, last_seen]);
    }
    let table = builder.build();
    println!("{}", table);
}

fn display_status(status: &DaemonStatus) {
    println!("=== Daemon Status ===");
    println!("Running: {}", status.running);
    println!("Paused: {}", status.paused);
    println!("Node Count: {}", status.node_count);
    println!("Client Count: {}", status.client_count);
    println!("Uptime: {}s", status.uptime_seconds);
    println!("My Domain: {}", status.my_domain);
    println!("My Address: {}", status.my_addr);
}

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;

    format!("{}Hour {}Min {}Sec ago", hours, minutes, seconds)
}

fn best_ip_for_display(addr: &iroh::EndpointAddr) -> Option<std::net::IpAddr> {
    let mut best_v6: Option<std::net::IpAddr> = None;
    for sock in addr.ip_addrs() {
        let ip = sock.ip();
        if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
            continue;
        }
        if ip.is_ipv4() {
            return Some(ip);
        }
        if best_v6.is_none() {
            best_v6 = Some(ip);
        }
    }
    best_v6
}

async fn send_message<T: serde::Serialize>(
    stream: &mut tokio::net::UnixStream,
    msg: &T,
) -> Result<()> {
    let msg_bytes = postcard::to_stdvec(msg)?;
    let len = msg_bytes.len() as u32;

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&msg_bytes).await?;

    Ok(())
}

async fn read_message<T: for<'a> serde::Deserialize<'a>>(
    stream: &mut tokio::net::UnixStream,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; len];
    stream.read_exact(&mut msg_buf).await?;

    let msg: T = postcard::from_bytes(&msg_buf)?;
    Ok(msg)
}
