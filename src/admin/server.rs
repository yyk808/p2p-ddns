use std::{io::ErrorKind, path::Path, path::PathBuf, sync::Arc};

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
    if let Some(path) = std::env::var_os("P2P_DDNS_SOCKET") {
        return PathBuf::from(path);
    }
    if let Some(xdg_runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(xdg_runtime).join("p2p-ddns.sock");
    } else if let Some(runtime_dir) = std::env::var_os("RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("p2p-ddns.sock");
    }
    PathBuf::from("/run/p2p-ddns.sock")
}

pub async fn run_management_server(
    socket_path: PathBuf,
    ctx: Arc<Context>,
    clients: Arc<ClientRegistry>,
) {
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).ok();
    }

    if let Some(parent) = socket_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            log_socket_setup_failure(
                "create management socket directory",
                parent,
                &socket_path,
                &e,
            );
            return;
        }
    }

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            log_socket_setup_failure("bind management socket", &socket_path, &socket_path, &e);
            return;
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&socket_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o660);
            let _ = std::fs::set_permissions(&socket_path, perms);
        }
    }

    info!("Management socket listening on: {}", socket_path.display());

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
) {
    if error.kind() == ErrorKind::PermissionDenied {
        warn!(
            "Could not {action} at {}: {error}. The daemon does not have permission to create the admin socket at {}. Re-run with sudo or set P2P_DDNS_SOCKET/XDG_RUNTIME_DIR/RUNTIME_DIR to a writable location.",
            target.display(),
            socket_path.display()
        );
    } else {
        error!("Failed to {action} at {}: {}", target.display(), error);
    }
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
