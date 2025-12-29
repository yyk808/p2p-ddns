use anyhow::Result;
use clap::Parser;
use base64::Engine;
use futures::TryStreamExt;
use iroh::{EndpointAddr, PublicKey};
use log::{error, info};
use p2p_ddns::{
    client_daemon_protocol::*,
    network::init_network,
    storage::init_storage,
    types::{ClientInfo, ClientPermissions, Message, SERVICE_MARKER_CLIENT, SERVICE_VALUE_CLIENT},
    utils::{DaemonArgs, time_now},
};
use std::{path::PathBuf, sync::Arc};
use tokio::net::UnixListener;

#[tokio::main]
async fn main() -> Result<()> {
    let args = DaemonArgs::parse();
    DaemonArgs::validate(&args)?;
    DaemonArgs::apply(&args);

    env_logger::Builder::new()
        .filter_level(args.log.into())
        .init();

    let storage = init_storage(&args).await?;
    let (ctx, gos_recv, sp_recv, rnum) = init_network(args.clone(), storage).await?;
    let ctx = Arc::new(ctx);

    info!("Ticket: {}", ctx.ticket);
    info!("Daemon started");

    let socket_path = get_socket_path();
    let ctx_clone = ctx.clone();

    tokio::spawn(async move {
        run_management_server(socket_path, ctx_clone).await;
    });

    ctx.run(gos_recv, sp_recv, rnum).await;
    Ok(())
}

fn get_socket_path() -> PathBuf {
    if let Some(xdg_runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(xdg_runtime).join("p2p-ddns.sock");
    } else if let Some(runtime_dir) = std::env::var_os("RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("p2p-ddns.sock");
    } else {
        return PathBuf::from("/run/p2p-ddns.sock");
    }
}

async fn run_management_server(socket_path: PathBuf, ctx: Arc<p2p_ddns::network::Context>) {
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).ok();
    }

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind management socket: {}", e);
            return;
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&socket_path)?.permissions();
        perms.set_mode(0o660);
        let _ = std::fs::set_permissions(&socket_path, perms);
    }

    info!("Management socket listening on: {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok(stream) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    handle_client_connection(stream, ctx).await;
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_client_connection(
    mut stream: tokio::net::UnixStream,
    ctx: Arc<p2p_ddns::network::Context>,
) {
    let auth_req = match read_message::<AuthRequest>(&mut stream).await {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to read AuthRequest: {}", e);
            return;
        }
    };

    let ticket_valid = match p2p_ddns::utils::Ticket::from_str(&auth_req.ticket) {
        Ok(ticket) => ticket.validate(ctx.ticket.topic(), ctx.ticket.rnum()),
        Err(_) => false,
    };

    if !ticket_valid {
        let response = AuthResponse {
            success: false,
            error: Some("Invalid ticket".to_string()),
            daemon_public_key: None,
        };
        let _ = send_message(&mut stream, &response).await;
        return;
    }

    let client_pk = match auth_req.client_public_key {
        Some(pk_str) => {
            match Engine::new(&base64::engine::general_purpose::STANDARD_NO_PAD)
                .decode(pk_str)
            {
                Ok(bytes) => match PublicKey::from_bytes(&bytes) {
                    Ok(pk) => Some(pk),
                    Err(_) => None,
                },
                Err(_) => None,
            }
        }
        None => None,
    };

    if let Some(pk) = client_pk {
        let client_node = p2p_ddns::types::Node {
            node_id: pk,
            invitor: ctx.me.node_id,
            addr: EndpointAddr::new(pk),
            domain: auth_req.client_name.unwrap_or_else(|| format!("client-{}", pk)),
            services: {
                let mut map = std::collections::BTreeMap::new();
                map.insert(SERVICE_MARKER_CLIENT.to_string(), SERVICE_VALUE_CLIENT);
                map
            },
            last_heartbeat: time_now(),
        };

        ctx.nodes.insert(pk, client_node.clone());

        let client_info = ClientInfo {
            connected_at: time_now(),
            ticket_used: auth_req.ticket.clone(),
            client_name: auth_req.client_name.clone(),
            permissions: ClientPermissions {
                can_query: true,
                can_add_node: true,
                can_remove_node: true,
                can_control: true,
            },
        };
        ctx.add_client(pk, client_info);

        let introduce_msg = Message::Introduce {
            invited: pk,
        };
        let _ = ctx.broadcast_message(introduce_msg).await;
        info!("Client {:?} introduced to network", pk);
    }

    let response = AuthResponse {
        success: true,
        error: None,
        daemon_public_key: Some(
            Engine::new(&base64::engine::general_purpose::STANDARD_NO_PAD)
                .encode(ctx.me.node_id.as_bytes())
        ),
    };

    if let Err(e) = send_message(&mut stream, &response).await {
        error!("Failed to send AuthResponse: {}", e);
        return;
    }

    if let Some(pk) = client_pk {
        loop {
            let cmd = match read_message::<ClientCommand>(&mut stream).await {
                Ok(c) => c,
                Err(_) => break,
            };

            let required_perm = match &cmd {
                ClientCommand::Query => "query",
                ClientCommand::AddNode { .. } => "add_node",
                ClientCommand::RemoveNode { .. } => "remove_node",
                ClientCommand::Status => "query",
                ClientCommand::GetTicket => "query",
                ClientCommand::Pause => "control",
                ClientCommand::Resume => "control",
                ClientCommand::Shutdown => "control",
            };

            let authorized = ctx.check_client_permission(&pk, required_perm);

            if !authorized {
                let response = ClientResponse::Error("Permission denied".to_string());
                let _ = send_message(&mut stream, &response).await;
                continue;
            }

            let response = handle_command(&cmd, &ctx).await;

            if let Err(e) = send_message(&mut stream, &response).await {
                error!("Failed to send response: {}", e);
                break;
            }
        }
    }
}

async fn handle_command(
    cmd: &ClientCommand,
    ctx: &p2p_ddns::network::Context>,
) -> ClientResponse {
    match cmd {
        ClientCommand::Query => {
            let nodes: Vec<p2p_ddns::types::Node> = ctx.nodes.iter()
                .filter(|e| !ctx.is_client_node(e.key()))
                .map(|e| e.value().clone())
                .collect();
            ClientResponse::Nodes(nodes)
        }

        ClientCommand::AddNode { .. } => {
            ClientResponse::Ack
        }

        ClientCommand::RemoveNode { .. } => {
            ClientResponse::Ack
        }

        ClientCommand::Status => {
            let status = p2p_ddns::types::DaemonStatus {
                running: true,
                paused: false,
                node_count: ctx.nodes.len(),
                client_count: ctx.client_count(),
                uptime_seconds: 0,
                my_domain: ctx.me.domain.clone(),
                my_addr: ctx.handle.addr().to_string(),
            };
            ClientResponse::Status(status)
        }

        ClientCommand::GetTicket => {
            ClientResponse::Ticket(ctx.ticket.to_string())
        }

        ClientCommand::Pause => {
            ClientResponse::Ack
        }

        ClientCommand::Resume => {
            ClientResponse::Ack
        }

        ClientCommand::Shutdown => {
            ctx.graceful_shutdown().await;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            std::process::exit(0);
        }
    }
}

async fn read_message<T: for<'a> serde::Deserialize<'a>>(
    stream: &mut tokio::net::UnixStream,
) -> anyhow::Result<T> {
    use tokio::io::{AsyncReadExt};

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; len];
    stream.read_exact(&mut msg_buf).await?;

    let msg: T = postcard::from_bytes(&msg_buf)?;
    Ok(msg)
}

async fn send_message<T: serde::Serialize>(
    stream: &mut tokio::net::UnixStream,
    msg: &T,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let msg_bytes = postcard::to_stdvec(msg)?;
    let len = msg_bytes.len() as u32;

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&msg_bytes).await?;

    Ok(())
}
