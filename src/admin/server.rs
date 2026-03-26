use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use log::{error, info, warn};
use tokio::net::UnixListener;

use crate::{
    admin::{
        authz::ClientRegistry,
        handler::{self, AdminAction, AuthMode},
        protocol::*,
    },
    net::Context,
};

pub fn default_socket_path() -> PathBuf {
    socket_path_candidates()
        .into_iter()
        .next()
        .unwrap_or_else(|| std::env::temp_dir().join("p2p-ddns").join("p2p-ddns.sock"))
}

pub fn socket_path_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    let push_candidate = |candidates: &mut Vec<PathBuf>, path: PathBuf| {
        if !candidates.iter().any(|existing| existing == &path) {
            candidates.push(path);
        }
    };

    if let Some(path) = std::env::var_os("P2P_DDNS_SOCKET") {
        push_candidate(&mut candidates, PathBuf::from(path));
        return candidates;
    }
    if let Some(xdg_runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        push_candidate(
            &mut candidates,
            PathBuf::from(xdg_runtime).join("p2p-ddns.sock"),
        );
    }
    if let Some(runtime_dir) = std::env::var_os("RUNTIME_DIR") {
        push_candidate(
            &mut candidates,
            PathBuf::from(runtime_dir).join("p2p-ddns.sock"),
        );
    }

    push_candidate(&mut candidates, PathBuf::from("/run/p2p-ddns.sock"));

    if let Some(runtime_dir) = dirs::runtime_dir() {
        push_candidate(&mut candidates, runtime_dir.join("p2p-ddns.sock"));
    }

    if let Some(cache_dir) = dirs::cache_dir() {
        push_candidate(
            &mut candidates,
            cache_dir.join("p2p-ddns").join("p2p-ddns.sock"),
        );
    }

    push_candidate(
        &mut candidates,
        std::env::temp_dir().join("p2p-ddns").join("p2p-ddns.sock"),
    );

    candidates
}

pub async fn run_default_management_server(ctx: Arc<Context>, clients: Arc<ClientRegistry>) {
    run_management_server_with_candidates(socket_path_candidates(), ctx, clients).await;
}

pub async fn run_management_server(
    socket_path: PathBuf,
    ctx: Arc<Context>,
    clients: Arc<ClientRegistry>,
) {
    run_management_server_with_candidates(vec![socket_path], ctx, clients).await;
}

async fn run_management_server_with_candidates(
    candidates: Vec<PathBuf>,
    ctx: Arc<Context>,
    clients: Arc<ClientRegistry>,
) {
    let total_candidates = candidates.len();

    for (index, socket_path) in candidates.into_iter().enumerate() {
        match try_bind_management_socket(&socket_path) {
            Ok(listener) => {
                info!("Management socket listening on: {}", socket_path.display());
                accept_loop(listener, ctx, clients).await;
                return;
            }
            Err(SocketSetupError {
                action,
                target,
                socket_path,
                error,
            }) => {
                let will_retry = index + 1 < total_candidates;
                log_socket_setup_failure(&action, &target, &socket_path, &error, will_retry);
            }
        }
    }

    error!("Failed to initialize the admin socket on any candidate path");
}

fn try_bind_management_socket(socket_path: &Path) -> Result<UnixListener, SocketSetupError> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path).ok();
    }

    if let Some(parent) = socket_path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Err(SocketSetupError {
            action: "create management socket directory".to_string(),
            target: parent.to_path_buf(),
            socket_path: socket_path.to_path_buf(),
            error,
        });
    }

    let listener = UnixListener::bind(socket_path).map_err(|error| SocketSetupError {
        action: "bind management socket".to_string(),
        target: socket_path.to_path_buf(),
        socket_path: socket_path.to_path_buf(),
        error,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(socket_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o660);
            let _ = std::fs::set_permissions(socket_path, perms);
        }
    }

    Ok(listener)
}

async fn accept_loop(listener: UnixListener, ctx: Arc<Context>, clients: Arc<ClientRegistry>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let ctx = ctx.clone();
                let clients = clients.clone();
                tokio::spawn(async move {
                    handle_client_connection(stream, ctx, clients).await;
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

fn log_socket_setup_failure(
    action: &str,
    target: &Path,
    socket_path: &Path,
    error: &std::io::Error,
    will_retry: bool,
) {
    if matches!(
        error.kind(),
        ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
    ) {
        warn!(
            "Could not {action} at {}: {error}. The daemon cannot create the admin socket at {}.{}",
            target.display(),
            socket_path.display(),
            if will_retry {
                " Trying the next socket path candidate."
            } else {
                " Re-run with sudo or set P2P_DDNS_SOCKET/XDG_RUNTIME_DIR/RUNTIME_DIR to a writable location."
            }
        );
    } else {
        error!(
            "Failed to {action} at {} for admin socket {}: {}{}",
            target.display(),
            socket_path.display(),
            error,
            if will_retry {
                "; trying the next socket path candidate"
            } else {
                ""
            }
        );
    }
}

struct SocketSetupError {
    action: String,
    target: PathBuf,
    socket_path: PathBuf,
    error: std::io::Error,
}

async fn handle_client_connection(
    mut stream: tokio::net::UnixStream,
    ctx: Arc<Context>,
    clients: Arc<ClientRegistry>,
) {
    let auth_req = match read_message::<AuthRequest>(&mut stream).await {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to read AuthRequest: {}", e);
            return;
        }
    };

    let (response, client_id) = match handler::authenticate_and_register(
        &ctx,
        &clients,
        &auth_req,
        AuthMode::AllowLocalTicketless,
    ) {
        Ok(res) => res,
        Err(e) => {
            error!("Auth handling error: {}", e);
            return;
        }
    };

    if let Err(e) = send_message(&mut stream, &response).await {
        error!("Failed to send AuthResponse: {}", e);
        return;
    }

    if let Some(pk) = client_id {
        loop {
            let cmd = match read_message::<ClientCommand>(&mut stream).await {
                Ok(c) => c,
                Err(_) => break,
            };

            let required_perm = handler::required_permission(&cmd);

            let authorized = clients.check_permission(&pk, required_perm);

            if !authorized {
                let response = ClientResponse::Error("Permission denied".to_string());
                let _ = send_message(&mut stream, &response).await;
                continue;
            }

            let outcome = handler::handle_command(&cmd, &ctx, &clients).await;

            if let Err(e) = send_message(&mut stream, &outcome.response).await {
                error!("Failed to send response: {}", e);
                break;
            }

            if outcome.action == Some(AdminAction::Shutdown) {
                ctx.graceful_shutdown().await;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                std::process::exit(0);
            }
        }
    }
}

async fn read_message<T: for<'a> serde::Deserialize<'a>>(
    stream: &mut tokio::net::UnixStream,
) -> Result<T> {
    use tokio::io::AsyncReadExt;

    const MAX_ADMIN_FRAME: usize = 4 * 1024 * 1024;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_ADMIN_FRAME {
        anyhow::bail!("admin frame too large: {}", len);
    }

    let mut msg_buf = vec![0u8; len];
    stream.read_exact(&mut msg_buf).await?;

    let msg: T = postcard::from_bytes(&msg_buf)?;
    Ok(msg)
}

async fn send_message<T: serde::Serialize>(
    stream: &mut tokio::net::UnixStream,
    msg: &T,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let msg_bytes = postcard::to_stdvec(msg)?;
    let len = msg_bytes.len() as u32;

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&msg_bytes).await?;

    Ok(())
}
