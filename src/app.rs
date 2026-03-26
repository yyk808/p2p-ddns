use std::{env, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use base64::Engine as _;
use clap::{Parser, Subcommand, builder::TypedValueParser};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::EnvFilter;

use crate::{
    admin::{authz::ClientRegistry, protocol::*},
    cli::{
        args::{DaemonArgs, LogLevel},
        output, paths,
    },
    net::init_network,
    storage, util,
};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "p2p-ddnsctl",
    version,
    about = "p2p-ddns local management client",
    long_about = None
)]
pub struct ClientArgs {
    /// Path to daemon's Unix socket; defaults to XDG_RUNTIME_DIR or /run.
    #[arg(long, value_name = "SOCKET_PATH")]
    pub socket_path: Option<PathBuf>,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,

    /// Optional network ticket. Current local daemons allow ticketless Unix socket access.
    #[arg(short, long, value_name = "TICKET")]
    pub ticket: Option<String>,

    /// Log level, default is info
    #[arg(
        long,
        short = 'L',
        default_value_t = LogLevel::Info,
        value_parser = clap::builder::PossibleValuesParser::new(["trace", "debug", "info", "warn", "error", "off"])
            .map(|s: String| s.parse::<LogLevel>().unwrap()),
    )]
    pub log: LogLevel,

    #[command(subcommand)]
    pub command: ClientCommandArgs,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ClientCommandArgs {
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

pub fn init_logging(level: LogLevel) {
    let default_filter = format!(
        "warn,p2p_ddns={},iroh::discovery::pkarr=error,tracing::span=warn",
        level
    );
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let _ = tracing_log::LogTracer::init();
    log::set_max_level(log::LevelFilter::Trace);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_level(true)
        .try_init();
}

pub async fn run_daemon(mut args: DaemonArgs) -> Result<()> {
    args.daemon = true;
    DaemonArgs::validate(&args)?;
    DaemonArgs::apply(&args);

    let db_path = paths::storage_db_path(&args);
    let storage = storage::open_or_create(db_path)?;
    let (ctx, gos_recv, sp_recv) = init_network(args.clone(), storage).await?;
    let ctx = Arc::new(ctx);
    let clients = Arc::new(ClientRegistry::new());

    output::print_bootstrap_ticket(&ctx);
    output::log_startup(&ctx);
    log::info!("Daemon started");

    if args.hosts_sync {
        sync_hosts_file(&ctx)?;
    }

    let socket_path = crate::admin::server::default_socket_path();
    tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        async move {
            crate::admin::server::run_management_server(socket_path, ctx, clients).await;
        }
    });

    if let Some(bind) = args.admin_http.as_deref() {
        let bind = util::parse_bind_addr(bind)?;
        tokio::spawn({
            let ctx = ctx.clone();
            let clients = clients.clone();
            async move {
                if let Err(e) = crate::admin::http::run_http_server(bind, ctx, clients).await {
                    log::error!("Admin HTTP server stopped: {}", e);
                }
            }
        });
    }

    spawn_daemon_background_tasks(ctx.clone(), args.hosts_sync);

    ctx.run(gos_recv, sp_recv).await;
    Ok(())
}

pub async fn run_client(args: ClientArgs) -> Result<()> {
    let socket_path = get_socket_path(&args.socket_path);
    let mut stream = connect_to_daemon(&socket_path, args.timeout).await?;
    let ticket = args.ticket.clone().or_else(|| get_ticket().ok());
    let _client_pk = authenticate(&mut stream, ticket.as_deref()).await?;
    execute_command(&mut stream, args.command).await?;
    Ok(())
}

fn spawn_daemon_background_tasks(ctx: Arc<crate::net::Context>, hosts_sync: bool) {
    tokio::spawn(async move {
        let mut print_tick = tokio::time::interval(Duration::from_secs(30));
        let mut hosts_tick = tokio::time::interval(Duration::from_secs(2));

        loop {
            tokio::select! {
                _ = print_tick.tick() => {
                    output::print(&ctx);
                }
                _ = hosts_tick.tick(), if hosts_sync => {
                    if let Err(e) = sync_hosts_file(&ctx) {
                        log::error!("Failed to synchronize hosts file: {e:#}");
                    }
                }
            }
        }
    });
}

fn sync_hosts_file(ctx: &crate::net::Context) -> Result<()> {
    let changed = ctx.sync_hosts_file()?;
    let status = ctx.hosts_sync_status();
    let hosts_path = status.path.unwrap_or_else(|| "/etc/hosts".to_string());
    if changed {
        log::info!("Synchronized hosts records to {hosts_path}");
    } else {
        log::debug!("Hosts records already up to date: {hosts_path}");
    }
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

    let default_path = crate::admin::server::default_socket_path();
    if default_path.exists() {
        return default_path;
    }

    let candidates = vec![
        env::var("XDG_RUNTIME_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("p2p-ddns.sock")),
        env::var("RUNTIME_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("p2p-ddns.sock")),
        Some(PathBuf::from("/run/p2p-ddns/p2p-ddns.sock")),
        Some(PathBuf::from("/run/p2p-ddns.sock")),
        Some(PathBuf::from("/var/run/p2p-ddns/p2p-ddns.sock")),
        Some(PathBuf::from("/var/run/p2p-ddns.sock")),
    ];

    for candidate in candidates {
        if let Some(path) = candidate
            && path.exists()
        {
            return path;
        }
    }

    default_path
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
    ticket: Option<&str>,
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
        ticket: ticket.unwrap_or_default().to_string(),
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
        log::info!("Authenticated successfully");
        Ok(pk)
    }
}

async fn execute_command(
    stream: &mut tokio::net::UnixStream,
    command: ClientCommandArgs,
) -> Result<()> {
    let cmd = match command {
        ClientCommandArgs::List => ClientCommand::Query,
        ClientCommandArgs::Status => ClientCommand::Status,
        ClientCommandArgs::AddNode { ticket } => ClientCommand::AddNode { ticket },
        ClientCommandArgs::RemoveNode { id } => ClientCommand::RemoveNode { id },
        ClientCommandArgs::GetTicket => ClientCommand::GetTicket,
        ClientCommandArgs::Pause => ClientCommand::Pause,
        ClientCommandArgs::Resume => ClientCommand::Resume,
        ClientCommandArgs::Stop => ClientCommand::Shutdown,
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
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&ticket_path) {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o600);
                        let _ = std::fs::set_permissions(&ticket_path, perms);
                    }
                }
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

async fn init_client_storage() -> Result<crate::storage::Storage> {
    let config_path = get_client_config_path();
    std::fs::create_dir_all(&config_path)?;

    let db_path = config_path.join("client.db");
    crate::storage::Storage::new(db_path)
}

fn get_client_config_path() -> PathBuf {
    dirs::config_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("p2p-ddns")
}

fn display_nodes(nodes: &[crate::domain::node::Node]) {
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

fn display_status(status: &crate::domain::client::DaemonStatus) {
    println!("=== Daemon Status ===");
    println!("Running: {}", status.running);
    println!("Paused: {}", status.paused);
    println!("Node Count: {}", status.node_count);
    println!("Client Count: {}", status.client_count);
    println!("Uptime: {}s", status.uptime_seconds);
    println!("My Domain: {}", status.my_domain);
    println!("My Address: {}", status.my_addr);
    println!("Hosts Sync Enabled: {}", status.hosts_sync.enabled);
    if let Some(path) = &status.hosts_sync.path {
        println!("Hosts Sync Path: {}", path);
    }
    println!(
        "Hosts Cleanup On Shutdown: {}",
        status.hosts_sync.cleanup_on_shutdown
    );
    if let Some(ts) = status.hosts_sync.last_success {
        println!("Hosts Sync Last Success: {}", ts);
    }
    if let Some(ts) = status.hosts_sync.last_cleanup {
        println!("Hosts Sync Last Cleanup: {}", ts);
    }
    if let Some(err) = &status.hosts_sync.last_error {
        println!("Hosts Sync Last Error: {}", err);
    }
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
    if len > 4 * 1024 * 1024 {
        anyhow::bail!("admin frame too large: {}", len);
    }
    let mut msg_buf = vec![0u8; len];
    stream.read_exact(&mut msg_buf).await?;
    Ok(postcard::from_bytes(&msg_buf)?)
}
