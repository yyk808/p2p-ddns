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

    /// Output results as JSON (useful for scripting and piping)
    #[arg(long, default_value_t = false)]
    pub json: bool,

    #[command(subcommand)]
    pub command: ClientCommandArgs,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ClientCommandArgs {
    /// List all network nodes
    List,

    /// Get daemon status
    Status,

    /// Manage nodes
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },

    /// Get current P2P ticket from daemon
    Ticket,

    /// Pause daemon
    Pause,

    /// Resume daemon
    Resume,

    /// Gracefully shutdown daemon
    Stop,
}

#[derive(Subcommand, Debug, Clone)]
pub enum NodeCommand {
    /// Add a node using a ticket
    Add {
        /// The ticket string from the other node
        ticket: String,
    },

    /// Remove a node by ID (supports prefix matching)
    Remove {
        /// Full or prefix of the node ID to remove
        id: String,
    },
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

    tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        async move {
            crate::admin::server::run_default_management_server(ctx, clients).await;
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
    execute_command(&mut stream, args.command, args.json).await?;
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

    let mut candidates = crate::admin::server::socket_path_candidates();
    for legacy_path in [
        PathBuf::from("/run/p2p-ddns/p2p-ddns.sock"),
        PathBuf::from("/var/run/p2p-ddns/p2p-ddns.sock"),
        PathBuf::from("/var/run/p2p-ddns.sock"),
    ] {
        if !candidates.iter().any(|path| path == &legacy_path) {
            candidates.push(legacy_path);
        }
    }

    for path in &candidates {
        if path.exists() {
            return path.clone();
        }
    }

    candidates
        .into_iter()
        .next()
        .unwrap_or_else(crate::admin::server::default_socket_path)
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
                    "Failed to connect to daemon at {} (timeout: {}s).\n\
                     Is the daemon running? Try: sudo systemctl start p2p-ddns",
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
        Ok(pk)
    }
}

async fn execute_command(
    stream: &mut tokio::net::UnixStream,
    command: ClientCommandArgs,
    json: bool,
) -> Result<()> {
    let cmd = match command {
        ClientCommandArgs::List => ClientCommand::Query,
        ClientCommandArgs::Status => ClientCommand::Status,
        ClientCommandArgs::Node {
            command: NodeCommand::Add { ticket },
        } => ClientCommand::AddNode { ticket },
        ClientCommandArgs::Node {
            command: NodeCommand::Remove { id },
        } => ClientCommand::RemoveNode { id },
        ClientCommandArgs::Ticket => ClientCommand::GetTicket,
        ClientCommandArgs::Pause => ClientCommand::Pause,
        ClientCommandArgs::Resume => ClientCommand::Resume,
        ClientCommandArgs::Stop => ClientCommand::Shutdown,
    };

    send_message(stream, &cmd).await?;
    let response: ClientResponse = read_message(stream).await?;

    match response {
        ClientResponse::Nodes(nodes) => {
            if json {
                output::display_nodes_json(&nodes);
            } else {
                output::display_nodes(&nodes);
            }
        }
        ClientResponse::Status(status) => {
            if json {
                output::display_status_json(&status);
            } else {
                output::display_status(&status);
            }
        }
        ClientResponse::Ticket(ticket) => {
            if json {
                output::display_ticket_json(&ticket);
            } else {
                output::display_ticket(&ticket);
            }
            let ticket_path = get_client_config_path().join("ticket.txt");
            if std::fs::write(&ticket_path, &ticket).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(&ticket_path) {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o600);
                        let _ = std::fs::set_permissions(&ticket_path, perms);
                    }
                }
                if !json {
                    output::display_info(&format!(
                        "Ticket saved to {}",
                        ticket_path.display()
                    ));
                }
            }
        }
        ClientResponse::Ack(message) => {
            if json {
                output::display_ack_json(&message);
            } else {
                output::display_ack(&message);
            }
        }
        ClientResponse::Error(e) => {
            if json {
                output::display_error_json(&e);
            } else {
                output::display_error(&e);
            }
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
