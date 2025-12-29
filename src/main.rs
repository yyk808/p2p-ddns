use std::{env, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use base64::Engine as _;
use clap::{ArgGroup, Parser, Subcommand};
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use p2p_ddns::{
    admin::{authz::ClientRegistry, protocol::*},
    cli::{args::DaemonArgs, output, paths},
    net::init_network,
    storage, util,
};

#[derive(Parser, Debug)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["daemon_mode", "client_mode"])
))]
struct AppArgs {
    /// Run the p2p-ddns daemon (node + management servers)
    #[arg(long = "daemon", conflicts_with = "client_mode")]
    daemon_mode: bool,

    /// Run as a management client (talk to a running daemon)
    #[arg(long = "client", conflicts_with = "daemon_mode")]
    client_mode: bool,

    /// Path to daemon's Unix socket (client mode); defaults to XDG_RUNTIME_DIR or /run.
    #[arg(long, value_name = "SOCKET_PATH")]
    socket_path: Option<PathBuf>,

    /// Request timeout in seconds (client mode)
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    #[command(subcommand)]
    client_command: Option<ClientCommands>,

    #[command(flatten)]
    node: DaemonArgs,
}

#[derive(Subcommand, Debug, Clone)]
enum ClientCommands {
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
    let mut args = AppArgs::parse();

    if args.daemon_mode {
        args.node.daemon = true;
        run_daemon(args.node).await
    } else {
        run_client(args).await
    }
}

async fn run_daemon(args: DaemonArgs) -> Result<()> {
    DaemonArgs::validate(&args)?;
    DaemonArgs::apply(&args);

    env_logger::Builder::new()
        .filter_level(args.log.into())
        .init();

    let db_path = paths::storage_db_path(&args);
    let storage = storage::open_or_create(db_path)?;
    let (ctx, gos_recv, sp_recv, rnum) = init_network(args.clone(), storage).await?;
    let ctx = Arc::new(ctx);
    let clients = Arc::new(ClientRegistry::new());

    info!("Ticket: {}", ctx.ticket);
    info!("Daemon started");

    let socket_path = p2p_ddns::admin::server::default_socket_path();
    tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        async move {
            p2p_ddns::admin::server::run_management_server(socket_path, ctx, clients).await;
        }
    });

    if let Some(bind) = args.admin_http.as_deref() {
        let bind = util::parse_bind_addr(bind)?;
        tokio::spawn({
            let ctx = ctx.clone();
            let clients = clients.clone();
            async move {
                if let Err(e) = p2p_ddns::admin::http::run_http_server(bind, ctx, clients).await {
                    log::error!("Admin HTTP server stopped: {}", e);
                }
            }
        });
    }

    tokio::spawn({
        let ctx = ctx.clone();
        async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                output::print(&ctx);
            }
        }
    });

    ctx.run(gos_recv, sp_recv, rnum).await;
    Ok(())
}

async fn run_client(args: AppArgs) -> Result<()> {
    let cmd = args.client_command.ok_or_else(|| {
        anyhow::anyhow!("Missing client command. Example: `p2p-ddns --client --socket /run/p2p-ddns.sock status`")
    })?;

    let ticket = match args.node.ticket.clone() {
        Some(t) => t,
        None => get_ticket()?,
    };

    let socket_path = get_socket_path(&args.socket_path);
    let mut stream = connect_to_daemon(&socket_path, args.timeout).await?;
    let _client_pk = authenticate(&mut stream, &ticket).await?;
    execute_command(&mut stream, cmd).await?;
    Ok(())
}

fn get_ticket() -> Result<String> {
    if let Ok(ticket) = env::var("P2P_DDNS_CLI_ARGS") {
        let args: Vec<String> = ticket.split_whitespace().map(|s| s.to_string()).collect();
        for (i, arg) in args.iter().enumerate() {
            if (arg == "--ticket" || arg == "-t")
                && let Some(ticket) = args.get(i + 1)
            {
                return Ok(ticket.clone());
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
        "No ticket found. Provide via --ticket, P2P_DDNS_TICKET env, or save to {}/ticket.txt",
        get_client_config_path().display()
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
        env::var("XDG_RUNTIME_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("p2p-ddns.sock")),
        env::var("RUNTIME_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("p2p-ddns.sock")),
        Some(PathBuf::from("/run/p2p-ddns.sock")),
        Some(PathBuf::from("/var/run/p2p-ddns.sock")),
    ];

    for candidate in candidates {
        if let Some(path) = candidate
            && path.exists()
        {
            return path;
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
    Ok(
        tokio::time::timeout(timeout, tokio::net::UnixStream::connect(socket_path))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Failed to connect to daemon at {} (timeout: {}s). Is daemon running?",
                    socket_path.display(),
                    timeout_sec
                )
            })??,
    )
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
        storage.save_secret(sk.clone()).ok();
        (pk, sk)
    });

    let auth_req = AuthRequest {
        ticket: ticket.to_string(),
        client_public_key: Some(
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(pk.as_bytes()),
        ),
        client_name: Some("cli".to_string()),
    };
    send_message(stream, &auth_req).await?;

    let auth_resp: AuthResponse = read_message(stream).await?;

    if !auth_resp.success {
        Err(anyhow::anyhow!(
            "Authentication failed: {}",
            auth_resp
                .error
                .unwrap_or_else(|| "Unknown error".to_string())
        ))
    } else {
        info!("Authenticated successfully");
        Ok(pk)
    }
}

async fn execute_command(
    stream: &mut tokio::net::UnixStream,
    command: ClientCommands,
) -> Result<()> {
    let cmd = match command {
        ClientCommands::List => ClientCommand::Query,
        ClientCommands::Status => ClientCommand::Status,
        ClientCommands::AddNode { ticket } => ClientCommand::AddNode { ticket },
        ClientCommands::RemoveNode { id } => ClientCommand::RemoveNode { id },
        ClientCommands::GetTicket => ClientCommand::GetTicket,
        ClientCommands::Pause => ClientCommand::Pause,
        ClientCommands::Resume => ClientCommand::Resume,
        ClientCommands::Stop => ClientCommand::Shutdown,
    };

    send_message(stream, &cmd).await?;
    let response: ClientResponse = read_message(stream).await?;

    match response {
        ClientResponse::Nodes(nodes) => display_nodes(&nodes),
        ClientResponse::Status(status) => display_status(&status),
        ClientResponse::Ticket(ticket) => {
            println!("Current P2P Ticket: {}", ticket);
            let ticket_path = get_client_config_path().join("ticket.txt");
            if let Err(e) = std::fs::write(&ticket_path, &ticket) {
                log::warn!("Failed to save ticket: {}", e);
            } else {
                log::info!("Ticket saved to {}", ticket_path.display());
            }
        }
        ClientResponse::Ack => println!("Command executed successfully"),
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

fn display_nodes(nodes: &[p2p_ddns::domain::node::Node]) {
    let now = util::time_now();
    let data = nodes
        .iter()
        .map(|node| {
            let addr = util::best_ip_for_display(&node.addr)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let alias = node.domain.clone();
            let last_seen = format_duration(now.saturating_sub(node.last_heartbeat));
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

fn display_status(status: &p2p_ddns::domain::client::DaemonStatus) {
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
    Ok(postcard::from_bytes(&msg_buf)?)
}
