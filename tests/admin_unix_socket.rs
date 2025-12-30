#![cfg(unix)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use base64::Engine as _;
use iroh::SecretKey;
use p2p_ddns::{
    admin::{authz::ClientRegistry, protocol::*, server},
    cli::args::DaemonArgs,
    net::init_network,
    storage::Storage,
};
use tempfile::tempdir;
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::UnixStream};

async fn make_ctx_and_clients() -> Result<(Arc<p2p_ddns::net::Context>, Arc<ClientRegistry>)> {
    let dir = tempdir()?;
    let mut args = DaemonArgs::default();
    args.daemon = true;
    args.primary = true;
    args.domain = Some("a".to_string());
    args.config = Some(dir.path().to_path_buf());
    args.bind = Some("127.0.0.1:0".to_string());
    args.no_mdns = true;
    args.dht = false;
    DaemonArgs::validate(&args)?;

    let storage = Storage::new(dir.path().join("storage.db"))?;
    let (ctx, _gos, _sp) = init_network(args, storage).await?;
    Ok((Arc::new(ctx), Arc::new(ClientRegistry::new())))
}

async fn connect_retry(path: &PathBuf) -> Result<UnixStream> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    loop {
        match UnixStream::connect(path).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e.into());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

async fn send_message<T: serde::Serialize>(stream: &mut UnixStream, msg: &T) -> Result<()> {
    let msg_bytes = postcard::to_stdvec(msg)?;
    let len = msg_bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&msg_bytes).await?;
    Ok(())
}

async fn read_message<T: for<'a> serde::Deserialize<'a>>(stream: &mut UnixStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut msg_buf = vec![0u8; len];
    stream.read_exact(&mut msg_buf).await?;
    Ok(postcard::from_bytes(&msg_buf)?)
}

#[tokio::test]
async fn unix_socket_management_roundtrip_get_ticket() -> Result<()> {
    let (ctx, clients) = make_ctx_and_clients().await?;

    let sock_dir = tempdir()?;
    let sock_path = sock_dir.path().join("p2p-ddns.sock");

    let srv = tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        let sock_path = sock_path.clone();
        async move {
            server::run_management_server(sock_path, ctx, clients).await;
        }
    });

    let mut stream = connect_retry(&sock_path).await?;

    let mut rng = rand::rng();
    let sk = SecretKey::generate(&mut rng);
    let pk = sk.public();
    let auth = AuthRequest {
        ticket: ctx.ticket.to_string(),
        client_public_key: Some(
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(pk.as_bytes()),
        ),
        client_name: Some("unix".to_string()),
    };

    send_message(&mut stream, &auth).await?;
    let resp: AuthResponse = read_message(&mut stream).await?;
    assert!(resp.success);

    send_message(&mut stream, &ClientCommand::GetTicket).await?;
    let resp: ClientResponse = read_message(&mut stream).await?;
    let got = match resp {
        ClientResponse::Ticket(t) => t,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    assert_eq!(got, ctx.ticket.to_string());

    srv.abort();
    Ok(())
}

#[tokio::test]
async fn unix_socket_auth_rejects_invalid_ticket() -> Result<()> {
    let (ctx, clients) = make_ctx_and_clients().await?;

    let sock_dir = tempdir()?;
    let sock_path = sock_dir.path().join("p2p-ddns.sock");

    let srv = tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        let sock_path = sock_path.clone();
        async move {
            server::run_management_server(sock_path, ctx, clients).await;
        }
    });

    let mut stream = connect_retry(&sock_path).await?;

    let mut rng = rand::rng();
    let sk = SecretKey::generate(&mut rng);
    let pk = sk.public();
    let auth = AuthRequest {
        ticket: "not-a-ticket".to_string(),
        client_public_key: Some(
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(pk.as_bytes()),
        ),
        client_name: Some("unix".to_string()),
    };

    send_message(&mut stream, &auth).await?;
    let resp: AuthResponse = read_message(&mut stream).await?;
    assert!(!resp.success);

    srv.abort();
    Ok(())
}
