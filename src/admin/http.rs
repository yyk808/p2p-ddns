use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::Result;
use log::{error, info};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::{
    admin::{
        authz::ClientRegistry,
        handler::{self, AdminAction},
        protocol::{AdminCommandRequest, AuthRequest, ClientResponse},
    },
    net::Context,
};

pub async fn run_http_server(
    bind: SocketAddr,
    ctx: Arc<Context>,
    clients: Arc<ClientRegistry>,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!("Admin HTTP listening on http://{}", bind);

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        let clients = clients.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(&mut stream, peer, &ctx, &clients).await {
                error!("Admin HTTP error ({}): {}", peer, e);
            }
        });
    }
}

async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    _peer: SocketAddr,
    ctx: &Context,
    clients: &ClientRegistry,
) -> Result<()> {
    let (method, path, headers, body) = read_http_request(stream).await?;

    if method != "POST" {
        return write_response(stream, 405, "text/plain", b"Method Not Allowed").await;
    }

    let content_type = headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("application/octet-stream");

    if content_type != "application/postcard" && content_type != "application/octet-stream" {
        return write_response(stream, 415, "text/plain", b"Unsupported Media Type").await;
    }

    match path.as_str() {
        "/auth" => {
            let auth_req: AuthRequest = postcard::from_bytes(&body)?;
            let (auth_resp, _client_id) =
                handler::authenticate_and_register(ctx, clients, &auth_req)?;
            let resp_body = postcard::to_stdvec(&auth_resp)?;
            write_response(stream, 200, "application/postcard", &resp_body).await
        }
        "/command" => {
            let req: AdminCommandRequest = postcard::from_bytes(&body)?;
            let (auth_resp, client_id) =
                handler::authenticate_and_register(ctx, clients, &req.auth)?;
            if !auth_resp.success {
                let resp_body = postcard::to_stdvec(&auth_resp)?;
                return write_response(stream, 401, "application/postcard", &resp_body).await;
            }

            let client_id = match client_id {
                Some(id) => id,
                None => {
                    let resp = ClientResponse::Error("Missing client_public_key".to_string());
                    let resp_body = postcard::to_stdvec(&resp)?;
                    return write_response(stream, 401, "application/postcard", &resp_body).await;
                }
            };

            let required = handler::required_permission(&req.command);
            if !clients.check_permission(&client_id, required) {
                let resp = ClientResponse::Error("Permission denied".to_string());
                let resp_body = postcard::to_stdvec(&resp)?;
                return write_response(stream, 403, "application/postcard", &resp_body).await;
            }

            let outcome = handler::handle_command(&req.command, ctx, clients).await;
            let resp_body = postcard::to_stdvec(&outcome.response)?;
            write_response(stream, 200, "application/postcard", &resp_body).await?;

            if outcome.action == Some(AdminAction::Shutdown) {
                ctx.graceful_shutdown().await;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                std::process::exit(0);
            }

            Ok(())
        }
        _ => write_response(stream, 404, "text/plain", b"Not Found").await,
    }
}

async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<(String, String, HashMap<String, String>, Vec<u8>)> {
    const MAX_BODY_SIZE: usize = 4 * 1024 * 1024;
    let mut buf = Vec::with_capacity(4096);
    let header_end;
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("connection closed");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 64 * 1024 {
            anyhow::bail!("request headers too large");
        }
    }

    let header_bytes = &buf[..header_end];
    let header_text = std::str::from_utf8(header_bytes)?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_len: usize = headers
        .get("content-length")
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(0);

    if content_len > MAX_BODY_SIZE {
        anyhow::bail!("request body too large");
    }

    let mut body = buf[header_end..].to_vec();
    if body.len() > MAX_BODY_SIZE {
        anyhow::bail!("request body too large");
    }
    while body.len() < content_len {
        let mut chunk = vec![0u8; content_len - body.len()];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("connection closed while reading body");
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > MAX_BODY_SIZE {
            anyhow::bail!("request body too large");
        }
    }

    Ok((method, path, headers, body))
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        _ => "OK",
    };

    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}
