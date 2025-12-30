use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use base64::Engine as _;
use iroh::SecretKey;
use p2p_ddns::{
    admin::{authz::ClientRegistry, http, protocol::*},
    cli::args::DaemonArgs,
    net::init_network,
    storage::Storage,
};
use tempfile::tempdir;
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

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

async fn connect_retry(addr: SocketAddr) -> Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    loop {
        match TcpStream::connect(addr).await {
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

async fn send_http_post(
    addr: SocketAddr,
    path: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>)> {
    let mut stream = connect_retry(addr).await?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(body).await?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;

    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("missing response header terminator"))?;
    let header = std::str::from_utf8(&resp[..header_end])?;
    let status = header
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or_else(|| anyhow::anyhow!("bad status line"))?
        .parse::<u16>()?;
    Ok((status, resp[header_end + 4..].to_vec()))
}

async fn send_http_get(addr: SocketAddr, path: &str) -> Result<u16> {
    let mut stream = connect_retry(addr).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;

    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("missing response header terminator"))?;
    let header = std::str::from_utf8(&resp[..header_end])?;
    let status = header
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or_else(|| anyhow::anyhow!("bad status line"))?
        .parse::<u16>()?;
    Ok(status)
}

#[tokio::test]
async fn http_auth_and_command_get_ticket_work_over_loopback() -> Result<()> {
    let (ctx, clients) = make_ctx_and_clients().await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let srv = tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        async move {
            let _ = http::run_http_server(addr, ctx, clients).await;
        }
    });

    let mut rng = rand::rng();
    let sk = SecretKey::generate(&mut rng);
    let pk = sk.public();
    let auth = AuthRequest {
        ticket: ctx.ticket.to_string(),
        client_public_key: Some(
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(pk.as_bytes()),
        ),
        client_name: Some("http".to_string()),
    };

    let body = postcard::to_stdvec(&auth)?;
    let (status, resp_body) = send_http_post(addr, "/auth", "application/postcard", &body).await?;
    assert_eq!(status, 200);
    let auth_resp: AuthResponse = postcard::from_bytes(&resp_body)?;
    assert!(auth_resp.success);

    let cmd_req = AdminCommandRequest {
        auth,
        command: ClientCommand::GetTicket,
    };
    let body = postcard::to_stdvec(&cmd_req)?;
    let (status, resp_body) =
        send_http_post(addr, "/command", "application/postcard", &body).await?;
    assert_eq!(status, 200);
    let resp: ClientResponse = postcard::from_bytes(&resp_body)?;
    let got = match resp {
        ClientResponse::Ticket(t) => t,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    assert_eq!(got, ctx.ticket.to_string());

    srv.abort();
    Ok(())
}

#[tokio::test]
async fn http_rejects_wrong_content_type() -> Result<()> {
    let (ctx, clients) = make_ctx_and_clients().await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let srv = tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        async move {
            let _ = http::run_http_server(addr, ctx, clients).await;
        }
    });

    let (status, _body) = send_http_post(addr, "/auth", "application/json", b"{}").await?;
    assert_eq!(status, 415);

    srv.abort();
    Ok(())
}

#[tokio::test]
async fn http_rejects_wrong_method_and_unknown_path() -> Result<()> {
    let (ctx, clients) = make_ctx_and_clients().await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let srv = tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        async move {
            let _ = http::run_http_server(addr, ctx, clients).await;
        }
    });

    assert_eq!(send_http_get(addr, "/auth").await?, 405);
    let (status, _body) = send_http_post(addr, "/nope", "application/postcard", b"").await?;
    assert_eq!(status, 404);

    srv.abort();
    Ok(())
}

#[tokio::test]
async fn http_command_rejects_invalid_ticket() -> Result<()> {
    let (ctx, clients) = make_ctx_and_clients().await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let srv = tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        async move {
            let _ = http::run_http_server(addr, ctx, clients).await;
        }
    });

    let bad_auth = AuthRequest {
        ticket: "not-a-ticket".to_string(),
        client_public_key: None,
        client_name: None,
    };
    let req = AdminCommandRequest {
        auth: bad_auth,
        command: ClientCommand::GetTicket,
    };
    let body = postcard::to_stdvec(&req)?;
    let (status, resp_body) =
        send_http_post(addr, "/command", "application/postcard", &body).await?;
    assert_eq!(status, 401);
    let auth_resp: AuthResponse = postcard::from_bytes(&resp_body)?;
    assert!(!auth_resp.success);

    srv.abort();
    Ok(())
}

#[tokio::test]
async fn http_command_requires_client_public_key() -> Result<()> {
    let (ctx, clients) = make_ctx_and_clients().await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let srv = tokio::spawn({
        let ctx = ctx.clone();
        let clients = clients.clone();
        async move {
            let _ = http::run_http_server(addr, ctx, clients).await;
        }
    });

    let auth = AuthRequest {
        ticket: ctx.ticket.to_string(),
        client_public_key: None,
        client_name: Some("http".to_string()),
    };
    let req = AdminCommandRequest {
        auth,
        command: ClientCommand::GetTicket,
    };
    let body = postcard::to_stdvec(&req)?;
    let (status, resp_body) =
        send_http_post(addr, "/command", "application/postcard", &body).await?;
    assert_eq!(status, 401);
    let resp: ClientResponse = postcard::from_bytes(&resp_body)?;
    assert!(matches!(resp, ClientResponse::Error(_)));

    srv.abort();
    Ok(())
}
