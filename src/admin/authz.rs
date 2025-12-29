use dashmap::DashMap;
use iroh::EndpointId;

use crate::domain::client::ClientInfo;

#[derive(Debug, Default)]
pub struct ClientRegistry {
    clients: DashMap<EndpointId, ClientInfo>,
}

impl ClientRegistry {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
        }
    }

    pub fn add_client(&self, node_id: EndpointId, info: ClientInfo) {
        self.clients.insert(node_id, info);
        log::info!("Client {:?} added", node_id);
    }

    pub fn remove_client(&self, node_id: &EndpointId) {
        self.clients.remove(node_id);
        log::info!("Client {:?} removed", node_id);
    }

    pub fn is_client_node(&self, node_id: &EndpointId) -> bool {
        self.clients.contains_key(node_id)
    }

    pub fn check_permission(&self, node_id: &EndpointId, perm: &str) -> bool {
        match self.clients.get(node_id) {
            Some(info) => match perm {
                "query" => info.permissions.can_query,
                "add_node" => info.permissions.can_add_node,
                "remove_node" => info.permissions.can_remove_node,
                "control" => info.permissions.can_control,
                _ => false,
            },
            None => false,
        }
    }

    pub fn count(&self) -> usize {
        self.clients.len()
    }
}
