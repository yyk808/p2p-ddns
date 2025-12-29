use serde::{Deserialize, Serialize};

/// Client节点标记（存储在Node.services中）
pub const SERVICE_MARKER_CLIENT: &str = "_p2p_ddns_client";

/// Client节点的服务数值
pub const SERVICE_VALUE_CLIENT: u32 = 1;

/// Client权限标记（存储在Node.services中）
pub const SERVICE_PERMISSION_QUERY: &str = "_perm_query";
pub const SERVICE_PERMISSION_ADD_NODE: &str = "_perm_add_node";
pub const SERVICE_PERMISSION_REMOVE_NODE: &str = "_perm_remove_node";
pub const SERVICE_PERMISSION_CONTROL: &str = "_perm_control";

/// Daemon状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub paused: bool,
    pub node_count: usize,
    pub client_count: usize,
    pub uptime_seconds: u64,
    pub my_domain: String,
    pub my_addr: String,
}

/// Client信息（存储在daemon的client registry中）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub connected_at: u64,
    pub ticket_used: String,
    pub client_name: Option<String>,
    pub permissions: ClientPermissions,
}

/// Client权限
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPermissions {
    pub can_query: bool,
    pub can_add_node: bool,
    pub can_remove_node: bool,
    pub can_control: bool,
}
