use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use base64::Engine as _;
use iroh::SecretKey;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::broadcast,
};

use crate::{
    admin::protocol::{
        AdminCommandRequest, AuthRequest, AuthResponse, ClientCommand, ClientResponse,
    },
    domain::node::Node,
    util,
};

const DEFAULT_MAX_BODY_SIZE: usize = 4 * 1024 * 1024;
const SECRET_HEADER: &str = "x-p2p-ddns-agent-secret";

#[derive(Debug, Clone)]
pub enum AdminEndpoint {
    UnixSocket(PathBuf),
    Http(SocketAddr),
}

#[derive(Debug, Clone)]
pub struct AdminClient {
    endpoint: AdminEndpoint,
    timeout: Duration,
    auth: AuthRequest,
}

impl AdminClient {
    pub fn new(endpoint: AdminEndpoint, timeout: Duration, ticket: Option<String>) -> Self {
        let mut rng = rand::rng();
        let pk = SecretKey::generate(&mut rng).public();
        let auth = AuthRequest {
            ticket: ticket.unwrap_or_default(),
            client_public_key: Some(
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(pk.as_bytes()),
            ),
            client_name: Some("agent-transport".to_string()),
        };
        Self {
            endpoint,
            timeout,
            auth,
        }
    }

    pub async fn resolve_node(&self, id_or_domain: &str) -> Result<Option<Node>> {
        let command = ClientCommand::ResolveNode {
            id_or_domain: id_or_domain.to_string(),
        };
        match self.execute(command).await? {
            ClientResponse::Node(node) => Ok(node),
            ClientResponse::Error(e) => anyhow::bail!(e),
            other => anyhow::bail!("unexpected admin response: {other:?}"),
        }
    }

    pub async fn query_nodes(&self) -> Result<Vec<Node>> {
        match self.execute(ClientCommand::Query).await? {
            ClientResponse::Nodes(nodes) => Ok(nodes),
            ClientResponse::Error(e) => anyhow::bail!(e),
            other => anyhow::bail!("unexpected admin response: {other:?}"),
        }
    }

    pub async fn set_service(&self, name: &str, port: u16) -> Result<()> {
        match self
            .execute(ClientCommand::SetService {
                name: name.to_string(),
                port: port as u32,
            })
            .await?
        {
            ClientResponse::Ack(msg) => {
                info!("Admin set_service: {}", msg);
                Ok(())
            }
            ClientResponse::Error(e) => anyhow::bail!(e),
            other => anyhow::bail!("unexpected admin response: {other:?}"),
        }
    }

    async fn execute(&self, command: ClientCommand) -> Result<ClientResponse> {
        match &self.endpoint {
            AdminEndpoint::UnixSocket(path) => {
                execute_socket_command(path, self.timeout, &self.auth, command).await
            }
            AdminEndpoint::Http(bind) => {
                execute_http_command(*bind, self.timeout, &self.auth, command).await
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub bind: SocketAddr,
    pub advertise_port: u16,
    pub local_id: String,
    pub admin: AdminClient,
    pub shared_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendRequest {
    pub to: String,
    pub text: String,
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteMessage {
    pub id: String,
    pub from: String,
    pub text: String,
    #[serde(default)]
    pub conversation_id: Option<String>,
    pub timestamp: u64,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportEvent {
    pub message: RemoteMessage,
    pub peer_addr: SocketAddr,
    pub received_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    pub id: String,
    pub node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<SocketAddr>,
    pub sendable: bool,
}

#[derive(Clone)]
struct TransportState {
    config: Arc<TransportConfig>,
    events: broadcast::Sender<TransportEvent>,
    next_id: Arc<AtomicU64>,
}

pub async fn run_transport(config: TransportConfig) -> Result<()> {
    let listener = TcpListener::bind(config.bind).await?;
    let (events, _) = broadcast::channel(1024);
    let state = TransportState {
        config: Arc::new(config),
        events,
        next_id: Arc::new(AtomicU64::new(1)),
    };

    if let Err(e) = state
        .config
        .admin
        .set_service("openclaw-agent", state.config.advertise_port)
        .await
    {
        warn!(
            "Failed to register service with p2p-ddns: {}. Service discovery may use fallback port.",
            e
        );
    }

    info!("Agent transport listening on http://{}", state.config.bind);
    loop {
        let (mut stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(&mut stream, peer, state).await {
                error!("Agent transport error ({}): {}", peer, e);
            }
        });
    }
}

pub fn transport_addr_for_node(node: &Node, port: u16) -> Option<SocketAddr> {
    let effective_port: u16 = node
        .services
        .get("openclaw-agent")
        .and_then(|&p| p.try_into().ok())
        .unwrap_or(port);
    let mut first = None;
    let mut first_ipv4_loopback = None;
    for candidate in node.addr.ip_addrs() {
        first.get_or_insert(*candidate);
        if candidate.ip().is_loopback() && candidate.ip().is_ipv4() {
            first_ipv4_loopback.get_or_insert(*candidate);
        }
        if !candidate.ip().is_loopback() {
            return Some(SocketAddr::new(candidate.ip(), effective_port));
        }
    }
    if let Some(addr) = first_ipv4_loopback {
        return Some(SocketAddr::new(addr.ip(), effective_port));
    }
    if first.is_some_and(|addr| addr.ip().is_loopback()) {
        return Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            effective_port,
        ));
    }
    first.map(|addr| SocketAddr::new(addr.ip(), effective_port))
}

pub fn transport_addr_for_node_with_local_ips(
    node: &Node,
    port: u16,
    local_ips: impl IntoIterator<Item = IpAddr>,
) -> Option<SocketAddr> {
    let locals: Vec<IpAddr> = local_ips.into_iter().collect();
    let mut best: Option<(u32, SocketAddr)> = None;
    for candidate in node.addr.ip_addrs() {
        let score = best_prefix_score(candidate.ip(), &locals);
        if best.as_ref().is_none_or(|(s, _)| score > *s) {
            best = Some((score, SocketAddr::new(candidate.ip(), port)));
        }
    }
    best.map(|(_, addr)| addr)
}

fn best_prefix_score(candidate: IpAddr, locals: &[IpAddr]) -> u32 {
    let mut best = 0u32;
    for local in locals {
        let score = common_prefix_len(candidate, *local);
        if score > best {
            best = score;
        }
    }
    best
}

fn common_prefix_len(a: IpAddr, b: IpAddr) -> u32 {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) ^ u32::from(b)).leading_zeros(),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a) ^ u128::from(b)).leading_zeros(),
        _ => 0,
    }
}

async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    peer: SocketAddr,
    state: TransportState,
) -> Result<()> {
    let (method, path, headers, body) = read_http_request(stream).await?;
    match (method.as_str(), path.as_str()) {
        ("GET", "/health") => {
            let body = serde_json::json!({ "ok": true });
            write_json_response(stream, 200, &body).await
        }
        ("GET", "/contacts") => {
            if !can_send_from_peer(peer, &headers, state.config.shared_secret.as_deref()) {
                let resp = SendResponse {
                    ok: false,
                    message_id: None,
                    error: Some("Forbidden".to_string()),
                };
                return write_json_response(stream, 403, &resp).await;
            }
            handle_contacts(stream, state).await
        }
        ("GET", "/events") => handle_events(stream, state).await,
        ("POST", "/send") => {
            if !can_send_from_peer(peer, &headers, state.config.shared_secret.as_deref()) {
                let resp = SendResponse {
                    ok: false,
                    message_id: None,
                    error: Some("Forbidden".to_string()),
                };
                return write_json_response(stream, 403, &resp).await;
            }
            handle_send(stream, body, state).await
        }
        ("POST", "/inbox") => {
            if !has_valid_secret(&headers, state.config.shared_secret.as_deref()) {
                let resp = SendResponse {
                    ok: false,
                    message_id: None,
                    error: Some("Forbidden".to_string()),
                };
                return write_json_response(stream, 403, &resp).await;
            }
            handle_inbox(stream, peer, body, state).await
        }
        _ => write_plain_response(stream, 404, b"Not Found").await,
    }
}

async fn handle_contacts(stream: &mut tokio::net::TcpStream, state: TransportState) -> Result<()> {
    match state.config.admin.query_nodes().await {
        Ok(nodes) => {
            let contacts =
                contacts_for_nodes(nodes, &state.config.local_id, state.config.advertise_port);
            write_json_response(stream, 200, &contacts).await
        }
        Err(e) => {
            let resp = SendResponse {
                ok: false,
                message_id: None,
                error: Some(format!("Failed to query nodes: {e}")),
            };
            write_json_response(stream, 502, &resp).await
        }
    }
}

pub fn contacts_for_nodes(
    nodes: impl IntoIterator<Item = Node>,
    local_id: &str,
    port: u16,
) -> Vec<Contact> {
    let mut contacts = nodes
        .into_iter()
        .filter_map(|node| contact_for_node(node, local_id, port))
        .collect::<Vec<_>>();
    contacts.sort_by(|a, b| a.id.cmp(&b.id));
    contacts
}

fn contact_for_node(node: Node, local_id: &str, port: u16) -> Option<Contact> {
    let node_id = node.node_id.to_string();
    let domain = node.domain.trim();
    let domain = (!domain.is_empty()).then(|| domain.to_string());
    let id = domain.clone().unwrap_or_else(|| node_id.clone());
    if id == local_id || node_id == local_id || domain.as_deref() == Some(local_id) {
        return None;
    }
    let addr = transport_addr_for_node(&node, port);
    let sendable = addr.is_some_and(|addr| !util::is_local_only_ip(addr.ip()));
    sendable.then(|| Contact {
        id,
        node_id,
        name: domain.clone(),
        domain,
        addr,
        sendable,
    })
}

fn can_send_from_peer(
    peer: SocketAddr,
    headers: &HashMap<String, String>,
    shared_secret: Option<&str>,
) -> bool {
    peer.ip().is_loopback()
        || shared_secret.is_some_and(|_| has_valid_secret(headers, shared_secret))
}

fn has_valid_secret(headers: &HashMap<String, String>, shared_secret: Option<&str>) -> bool {
    match shared_secret {
        Some(expected) => headers
            .get(SECRET_HEADER)
            .is_some_and(|actual| actual == expected),
        None => true,
    }
}

async fn handle_send(
    stream: &mut tokio::net::TcpStream,
    body: Vec<u8>,
    state: TransportState,
) -> Result<()> {
    let req: SendRequest = serde_json::from_slice(&body)?;
    if req.to.trim().is_empty() {
        let resp = SendResponse {
            ok: false,
            message_id: None,
            error: Some("Destination is required".to_string()),
        };
        return write_json_response(stream, 400, &resp).await;
    }
    if req.text.trim().is_empty() {
        let resp = SendResponse {
            ok: false,
            message_id: None,
            error: Some("Message text is required".to_string()),
        };
        return write_json_response(stream, 400, &resp).await;
    }

    let node = match state.config.admin.resolve_node(&req.to).await {
        Ok(Some(node)) => {
            log::debug!(
                "Resolved '{}' -> services={:?}, addrs={:?}",
                req.to,
                node.services,
                node.addr.ip_addrs().collect::<Vec<_>>()
            );
            node
        }
        Ok(None) => {
            let resp = SendResponse {
                ok: false,
                message_id: None,
                error: Some(format!("Node '{}' was not found", req.to)),
            };
            return write_json_response(stream, 404, &resp).await;
        }
        Err(e) => {
            let resp = SendResponse {
                ok: false,
                message_id: None,
                error: Some(format!("Failed to resolve node '{}': {e}", req.to)),
            };
            return write_json_response(stream, 502, &resp).await;
        }
    };
    let Some(target) = transport_addr_for_node(&node, state.config.advertise_port) else {
        let resp = SendResponse {
            ok: false,
            message_id: None,
            error: Some(format!("Node '{}' has no direct IP address", req.to)),
        };
        return write_json_response(stream, 502, &resp).await;
    };

    let message_id = format!(
        "{}-{}",
        util::time_now(),
        state.next_id.fetch_add(1, Ordering::Relaxed)
    );
    let message = RemoteMessage {
        id: message_id.clone(),
        from: state.config.local_id.clone(),
        text: req.text,
        conversation_id: req.conversation_id,
        timestamp: util::time_now(),
        metadata: req.metadata,
    };

    let (status, response_body) = send_json_post(
        target,
        "/inbox",
        &message,
        state.config.shared_secret.as_deref(),
        Duration::from_secs(10),
    )
    .await?;
    if !(200..300).contains(&status) {
        let error = String::from_utf8_lossy(&response_body).to_string();
        let resp = SendResponse {
            ok: false,
            message_id: Some(message_id),
            error: Some(format!("Remote inbox returned HTTP {status}: {error}")),
        };
        return write_json_response(stream, 502, &resp).await;
    }

    let resp = SendResponse {
        ok: true,
        message_id: Some(message_id),
        error: None,
    };
    write_json_response(stream, 200, &resp).await
}

async fn handle_inbox(
    stream: &mut tokio::net::TcpStream,
    peer: SocketAddr,
    body: Vec<u8>,
    state: TransportState,
) -> Result<()> {
    let message: RemoteMessage = serde_json::from_slice(&body)?;
    let event = TransportEvent {
        message: message.clone(),
        peer_addr: peer,
        received_at: util::time_now(),
    };
    if let Err(e) = state.events.send(event) {
        warn!(
            "No local event subscribers for inbound message {}: {}",
            message.id, e
        );
    }
    let resp = SendResponse {
        ok: true,
        message_id: Some(message.id),
        error: None,
    };
    write_json_response(stream, 200, &resp).await
}

async fn handle_events(stream: &mut tokio::net::TcpStream, state: TransportState) -> Result<()> {
    let headers = "HTTP/1.1 200 OK\r\n\
Content-Type: text/event-stream\r\n\
Cache-Control: no-cache\r\n\
Connection: keep-alive\r\n\r\n";
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(b": connected\n\n").await?;

    let mut rx = state.events.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => {
                let data = serde_json::to_string(&event)?;
                stream
                    .write_all(format!("event: message\ndata: {data}\n\n").as_bytes())
                    .await?;
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                stream
                    .write_all(format!("event: lagged\ndata: {skipped}\n\n").as_bytes())
                    .await?;
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<(String, String, HashMap<String, String>, Vec<u8>)> {
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

    let header_text = std::str::from_utf8(&buf[..header_end])?;
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
    if content_len > DEFAULT_MAX_BODY_SIZE {
        anyhow::bail!("request body too large");
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_len {
        let mut chunk = vec![0u8; content_len - body.len()];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("connection closed while reading body");
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > DEFAULT_MAX_BODY_SIZE {
            anyhow::bail!("request body too large");
        }
    }

    Ok((method, path, headers, body))
}

async fn write_json_response<T: Serialize>(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(body)?;
    write_response(stream, status, "application/json", &bytes).await
}

async fn write_plain_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &[u8],
) -> Result<()> {
    write_response(stream, status, "text/plain", body).await
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = reason_phrase(status);
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    }
}

async fn send_json_post<T: Serialize>(
    bind: SocketAddr,
    path: &str,
    body: &T,
    shared_secret: Option<&str>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>)> {
    let request_body = serde_json::to_vec(body)?;
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(bind))
        .await
        .map_err(|_| anyhow::anyhow!("failed to connect to {bind}"))??;

    let secret_header = shared_secret
        .map(|secret| format!("{SECRET_HEADER}: {secret}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        host_header(bind),
        secret_header,
        request_body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&request_body).await?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;
    parse_http_response(&resp)
}

#[cfg(test)]
async fn send_http_get(
    bind: SocketAddr,
    path: &str,
    shared_secret: Option<&str>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>)> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(bind))
        .await
        .map_err(|_| anyhow::anyhow!("failed to connect to {bind}"))??;

    let secret_header = shared_secret
        .map(|secret| format!("{SECRET_HEADER}: {secret}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
        host_header(bind),
        secret_header,
    );
    stream.write_all(request.as_bytes()).await?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;
    parse_http_response(&resp)
}

fn parse_http_response(resp: &[u8]) -> Result<(u16, Vec<u8>)> {
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("missing response header terminator"))?;
    let header = std::str::from_utf8(&resp[..header_end])?;
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| anyhow::anyhow!("bad status line"))?
        .parse::<u16>()?;
    Ok((status, resp[header_end + 4..].to_vec()))
}

fn host_header(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ip) => format!("{}:{}", ip, addr.port()),
        IpAddr::V6(ip) => format!("[{}]:{}", ip, addr.port()),
    }
}

async fn execute_http_command(
    bind: SocketAddr,
    timeout: Duration,
    auth: &AuthRequest,
    command: ClientCommand,
) -> Result<ClientResponse> {
    let request = AdminCommandRequest {
        auth: auth.clone(),
        command,
    };
    let (status, resp_body) = send_postcard_post(bind, timeout, "/command", &request).await?;
    match status {
        200 | 403 => Ok(postcard::from_bytes(&resp_body)?),
        401 => {
            let auth_resp: AuthResponse = postcard::from_bytes(&resp_body)?;
            anyhow::bail!(
                "authentication failed: {}",
                auth_resp
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            )
        }
        _ => anyhow::bail!("admin HTTP command failed with status {}", status),
    }
}

async fn send_postcard_post<T: Serialize>(
    bind: SocketAddr,
    timeout: Duration,
    path: &str,
    body: &T,
) -> Result<(u16, Vec<u8>)> {
    let request_body = postcard::to_stdvec(body)?;
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(bind))
        .await
        .map_err(|_| anyhow::anyhow!("failed to connect to admin HTTP endpoint at {bind}"))??;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/postcard\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        host_header(bind),
        request_body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&request_body).await?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;
    parse_http_response(&resp)
}

#[cfg(unix)]
async fn execute_socket_command(
    path: &PathBuf,
    timeout: Duration,
    auth: &AuthRequest,
    command: ClientCommand,
) -> Result<ClientResponse> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::UnixStream::connect(path))
        .await
        .map_err(|_| anyhow::anyhow!("failed to connect to daemon at {}", path.display()))??;
    send_admin_frame(&mut stream, auth).await?;
    let auth_resp: AuthResponse = read_admin_frame(&mut stream).await?;
    if !auth_resp.success {
        anyhow::bail!(
            "authentication failed: {}",
            auth_resp
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }
    send_admin_frame(&mut stream, &command).await?;
    read_admin_frame(&mut stream).await
}

#[cfg(not(unix))]
async fn execute_socket_command(
    _path: &PathBuf,
    _timeout: Duration,
    _auth: &AuthRequest,
    _command: ClientCommand,
) -> Result<ClientResponse> {
    anyhow::bail!("local socket admin is unavailable on this platform; use --admin-http")
}

#[cfg(unix)]
async fn read_admin_frame<T: for<'a> Deserialize<'a>>(
    stream: &mut tokio::net::UnixStream,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > DEFAULT_MAX_BODY_SIZE {
        anyhow::bail!("admin frame too large: {}", len);
    }

    let mut msg_buf = vec![0u8; len];
    stream.read_exact(&mut msg_buf).await?;
    Ok(postcard::from_bytes(&msg_buf)?)
}

#[cfg(unix)]
async fn send_admin_frame<T: Serialize>(
    stream: &mut tokio::net::UnixStream,
    msg: &T,
) -> Result<()> {
    let msg_bytes = postcard::to_stdvec(msg)?;
    stream
        .write_all(&(msg_bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&msg_bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use iroh::{EndpointAddr, TransportAddr};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn transport_addr_rewrites_discovered_ip_to_message_port() {
        let mut rng = rand::rng();
        let pk = SecretKey::generate(&mut rng).public();
        let p2p_addr: SocketAddr = "192.168.1.20:7777".parse().unwrap();
        let node = Node {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::from_parts(pk, [TransportAddr::Ip(p2p_addr)]),
            domain: "agent-b".to_string(),
            services: BTreeMap::new(),
            last_heartbeat: 1,
        };

        assert_eq!(
            transport_addr_for_node(&node, 39091),
            Some("192.168.1.20:39091".parse().unwrap())
        );
    }

    #[test]
    fn transport_addr_uses_advertised_openclaw_service_port() {
        let mut rng = rand::rng();
        let pk = SecretKey::generate(&mut rng).public();
        let p2p_addr: SocketAddr = "192.168.1.20:7777".parse().unwrap();
        let mut services = BTreeMap::new();
        services.insert("openclaw-agent".to_string(), 39092);
        let node = Node {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::from_parts(pk, [TransportAddr::Ip(p2p_addr)]),
            domain: "agent-b".to_string(),
            services,
            last_heartbeat: 1,
        };

        assert_eq!(
            transport_addr_for_node(&node, 39091),
            Some("192.168.1.20:39092".parse().unwrap())
        );
    }

    #[test]
    fn transport_addr_prefers_candidate_nearest_local_ip() {
        let mut rng = rand::rng();
        let pk = SecretKey::generate(&mut rng).public();
        let remote_a: SocketAddr = "10.10.0.5:7777".parse().unwrap();
        let remote_b: SocketAddr = "192.168.1.20:7777".parse().unwrap();
        let node = Node {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::from_parts(
                pk,
                [TransportAddr::Ip(remote_a), TransportAddr::Ip(remote_b)],
            ),
            domain: "agent-b".to_string(),
            services: BTreeMap::new(),
            last_heartbeat: 1,
        };

        assert_eq!(
            transport_addr_for_node_with_local_ips(&node, 39091, ["192.168.1.2".parse().unwrap()]),
            Some("192.168.1.20:39091".parse().unwrap())
        );
    }

    #[test]
    fn transport_addr_skips_loopback_when_lan_ip_exists() {
        let mut rng = rand::rng();
        let pk = SecretKey::generate(&mut rng).public();
        let loopback: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let lan: SocketAddr = "10.1.2.3:7777".parse().unwrap();
        let node = Node {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::from_parts(
                pk,
                [TransportAddr::Ip(loopback), TransportAddr::Ip(lan)],
            ),
            domain: "agent-b".to_string(),
            services: BTreeMap::new(),
            last_heartbeat: 1,
        };

        assert_eq!(
            transport_addr_for_node(&node, 39091),
            Some("10.1.2.3:39091".parse().unwrap())
        );
    }

    #[test]
    fn transport_addr_prefers_ipv4_when_only_loopback_candidates_exist() {
        let mut rng = rand::rng();
        let pk = SecretKey::generate(&mut rng).public();
        let loopback_v6: SocketAddr = "[::1]:7777".parse().unwrap();
        let loopback_v4: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let node = Node {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::from_parts(
                pk,
                [
                    TransportAddr::Ip(loopback_v6),
                    TransportAddr::Ip(loopback_v4),
                ],
            ),
            domain: "agent-b".to_string(),
            services: BTreeMap::new(),
            last_heartbeat: 1,
        };

        assert_eq!(
            transport_addr_for_node(&node, 39091),
            Some("127.0.0.1:39091".parse().unwrap())
        );
    }

    #[test]
    fn transport_addr_normalizes_ipv6_loopback_to_ipv4_loopback() {
        let mut rng = rand::rng();
        let pk = SecretKey::generate(&mut rng).public();
        let loopback_v6: SocketAddr = "[::1]:7777".parse().unwrap();
        let node = Node {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::from_parts(pk, [TransportAddr::Ip(loopback_v6)]),
            domain: "agent-b".to_string(),
            services: BTreeMap::new(),
            last_heartbeat: 1,
        };

        assert_eq!(
            transport_addr_for_node(&node, 39091),
            Some("127.0.0.1:39091".parse().unwrap())
        );
    }

    #[test]
    fn non_loopback_send_requires_configured_secret() {
        let peer: SocketAddr = "192.168.1.5:40000".parse().unwrap();
        let headers = HashMap::new();
        assert!(!can_send_from_peer(peer, &headers, None));

        let mut headers = HashMap::new();
        headers.insert(SECRET_HEADER.to_string(), "secret".to_string());
        assert!(can_send_from_peer(peer, &headers, Some("secret")));
        assert!(!can_send_from_peer(peer, &headers, Some("other")));
    }

    #[tokio::test]
    async fn send_resolves_node_and_delivers_to_peer_inbox() -> Result<()> {
        let mut rng = rand::rng();
        let target_pk = SecretKey::generate(&mut rng).public();

        let target_listener = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = target_listener.local_addr()?;
        let target_state = test_state("target", target_addr.port(), None);
        let mut target_events = target_state.events.subscribe();
        tokio::spawn(async move {
            let (mut stream, peer) = target_listener.accept().await.unwrap();
            handle_connection(&mut stream, peer, target_state)
                .await
                .unwrap();
        });

        let admin_listener = TcpListener::bind("127.0.0.1:0").await?;
        let admin_addr = admin_listener.local_addr()?;
        tokio::spawn(async move {
            let (mut stream, _) = admin_listener.accept().await.unwrap();
            let (_method, path, _headers, body) = read_http_request(&mut stream).await.unwrap();
            assert_eq!(path, "/command");
            let req: AdminCommandRequest = postcard::from_bytes(&body).unwrap();
            assert!(matches!(
                req.command,
                ClientCommand::ResolveNode { ref id_or_domain } if id_or_domain == "target"
            ));

            let advertised_p2p: SocketAddr = "127.0.0.1:7777".parse().unwrap();
            let node = Node {
                node_id: target_pk,
                invitor: target_pk,
                addr: EndpointAddr::from_parts(target_pk, [TransportAddr::Ip(advertised_p2p)]),
                domain: "target".to_string(),
                services: BTreeMap::new(),
                last_heartbeat: 1,
            };
            let resp = ClientResponse::Node(Some(node));
            let body = postcard::to_stdvec(&resp).unwrap();
            write_response(&mut stream, 200, "application/postcard", &body)
                .await
                .unwrap();
        });

        let send_listener = TcpListener::bind("127.0.0.1:0").await?;
        let send_addr = send_listener.local_addr()?;
        let send_state = test_state("source", target_addr.port(), Some(admin_addr));
        tokio::spawn(async move {
            let (mut stream, peer) = send_listener.accept().await.unwrap();
            handle_connection(&mut stream, peer, send_state)
                .await
                .unwrap();
        });

        let req = SendRequest {
            to: "target".to_string(),
            text: "hello".to_string(),
            conversation_id: Some("conv-1".to_string()),
            metadata: BTreeMap::new(),
        };
        let (status, body) =
            send_json_post(send_addr, "/send", &req, None, Duration::from_secs(5)).await?;
        assert_eq!(status, 200);
        let resp: SendResponse = serde_json::from_slice(&body)?;
        assert!(resp.ok);

        let event = tokio::time::timeout(Duration::from_secs(5), target_events.recv()).await??;
        assert_eq!(event.message.from, "source");
        assert_eq!(event.message.text, "hello");
        assert_eq!(event.message.conversation_id.as_deref(), Some("conv-1"));

        Ok(())
    }

    #[tokio::test]
    async fn contacts_query_admin_nodes_and_return_sendable_peers() -> Result<()> {
        let mut rng = rand::rng();
        let self_pk = SecretKey::generate(&mut rng).public();
        let peer_pk = SecretKey::generate(&mut rng).public();
        let local_only_pk = SecretKey::generate(&mut rng).public();

        let admin_listener = TcpListener::bind("127.0.0.1:0").await?;
        let admin_addr = admin_listener.local_addr()?;
        tokio::spawn(async move {
            let (mut stream, _) = admin_listener.accept().await.unwrap();
            let (_method, path, _headers, body) = read_http_request(&mut stream).await.unwrap();
            assert_eq!(path, "/command");
            let req: AdminCommandRequest = postcard::from_bytes(&body).unwrap();
            assert!(matches!(req.command, ClientCommand::Query));

            let self_node = test_node(self_pk, "agent-a", "10.1.0.1:7777");
            let peer_node = test_node(peer_pk, "agent-b", "10.1.0.2:7777");
            let local_only_node = test_node(local_only_pk, "agent-local", "127.0.0.1:7777");
            let resp = ClientResponse::Nodes(vec![self_node, peer_node, local_only_node]);
            let body = postcard::to_stdvec(&resp).unwrap();
            write_response(&mut stream, 200, "application/postcard", &body)
                .await
                .unwrap();
        });

        let contacts_listener = TcpListener::bind("127.0.0.1:0").await?;
        let contacts_addr = contacts_listener.local_addr()?;
        let contacts_state = test_state("agent-a", 39091, Some(admin_addr));
        tokio::spawn(async move {
            let (mut stream, peer) = contacts_listener.accept().await.unwrap();
            handle_connection(&mut stream, peer, contacts_state)
                .await
                .unwrap();
        });

        let (status, body) =
            send_http_get(contacts_addr, "/contacts", None, Duration::from_secs(5)).await?;
        assert_eq!(status, 200);
        let contacts: Vec<Contact> = serde_json::from_slice(&body)?;

        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].id, "agent-b");
        assert_eq!(contacts[0].domain.as_deref(), Some("agent-b"));
        assert_eq!(contacts[0].addr, Some("10.1.0.2:39091".parse().unwrap()));
        assert!(contacts[0].sendable);

        Ok(())
    }

    fn test_state(
        local_id: &str,
        advertise_port: u16,
        admin_addr: Option<SocketAddr>,
    ) -> TransportState {
        let admin_endpoint = admin_addr
            .map(AdminEndpoint::Http)
            .unwrap_or_else(|| AdminEndpoint::Http("127.0.0.1:9".parse().unwrap()));
        let (events, _) = broadcast::channel(16);
        TransportState {
            config: Arc::new(TransportConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                advertise_port,
                local_id: local_id.to_string(),
                admin: AdminClient::new(admin_endpoint, Duration::from_secs(5), None),
                shared_secret: None,
            }),
            events,
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    fn test_node(pk: iroh::PublicKey, domain: &str, addr: &str) -> Node {
        let p2p_addr: SocketAddr = addr.parse().unwrap();
        Node {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::from_parts(pk, [TransportAddr::Ip(p2p_addr)]),
            domain: domain.to_string(),
            services: BTreeMap::new(),
            last_heartbeat: 1,
        }
    }
}
