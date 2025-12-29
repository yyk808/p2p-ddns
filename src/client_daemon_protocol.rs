use crate::types::{Node, DaemonStatus};
use serde::{Deserialize, Serialize};

/// Client到Daemon的认证请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub ticket: String,
    pub client_public_key: Option<String>,  // Base64编码的公钥
    pub client_name: Option<String>,
}

/// Daemon到Client的认证响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub error: Option<String>,
    pub daemon_public_key: Option<String>,  // Daemon的公钥（base64编码）
}

/// Client管理命令
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientCommand {
    Query,
    AddNode { ticket: String },
    RemoveNode { id: String },
    Status,
    GetTicket,
    Pause,
    Resume,
    Shutdown,
}

/// Daemon响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientResponse {
    Nodes(Vec<Node>),
    Status(DaemonStatus),
    Ticket(String),
    Ack,
    Error(String),
}
