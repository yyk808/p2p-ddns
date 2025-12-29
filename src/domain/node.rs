use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub node_id: EndpointId,
    pub invitor: EndpointId,
    pub addr: EndpointAddr,
    pub domain: String,
    pub services: BTreeMap<String, u32>,
    pub last_heartbeat: u64,
}

#[cfg(test)]
impl Node {
    pub fn random_node() -> Self {
        let mut rng = rand::rng();
        let sk = iroh::SecretKey::generate(&mut rng);
        let pk = sk.public();

        Self {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::new(pk),
            domain: String::new(),
            services: BTreeMap::new(),
            last_heartbeat: 0,
        }
    }
}

impl Hash for Node {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.node_id.hash(state);
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
    }
}

impl Eq for Node {}
