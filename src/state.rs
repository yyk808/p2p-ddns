use std::collections::HashMap;

use iroh::{EndpointAddr, EndpointId};

use crate::types::Node;

pub fn has_ip_addr(addr: &EndpointAddr) -> bool {
    addr.ip_addrs().next().is_some()
}

pub fn merge_addr(existing: &EndpointAddr, incoming: &EndpointAddr) -> EndpointAddr {
    if has_ip_addr(incoming) {
        return incoming.clone();
    }
    if has_ip_addr(existing) {
        return existing.clone();
    }
    incoming.clone()
}

pub fn merge_node(existing: Option<&Node>, incoming: &Node) -> (Node, bool) {
    match existing {
        None => (incoming.clone(), true),
        Some(existing) => {
            let addr = merge_addr(&existing.addr, &incoming.addr);
            let should_take_incoming = incoming.last_heartbeat > existing.last_heartbeat;

            let merged = if should_take_incoming {
                Node {
                    addr,
                    ..incoming.clone()
                }
            } else {
                Node {
                    addr,
                    ..existing.clone()
                }
            };

            (merged, true)
        }
    }
}

pub fn ids_to_remove_for_duplicate_domains(nodes: &[Node]) -> Vec<EndpointId> {
    let mut by_domain: HashMap<&str, (EndpointId, u64)> = HashMap::new();
    for node in nodes {
        by_domain
            .entry(node.domain.as_str())
            .and_modify(|(best_id, best_heartbeat)| {
                if node.last_heartbeat > *best_heartbeat {
                    *best_id = node.node_id;
                    *best_heartbeat = node.last_heartbeat;
                }
            })
            .or_insert((node.node_id, node.last_heartbeat));
    }

    let mut to_remove = Vec::new();
    for node in nodes {
        if let Some((best_id, _)) = by_domain.get(node.domain.as_str())
            && *best_id != node.node_id
        {
            to_remove.push(node.node_id);
        }
    }
    to_remove
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::SocketAddr};

    use anyhow::Result;
    use iroh::{EndpointAddr, SecretKey, TransportAddr};

    use super::*;

    fn node_with_addr(addr: EndpointAddr, last_heartbeat: u64) -> Node {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();
        Node {
            node_id: pk,
            invitor: pk,
            addr,
            domain: "n".to_string(),
            services: BTreeMap::new(),
            last_heartbeat,
        }
    }

    #[test]
    fn merge_addr_keeps_existing_when_incoming_empty() -> Result<()> {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let ip: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let existing = EndpointAddr::from_parts(pk, [TransportAddr::Ip(ip)]);
        let incoming = EndpointAddr::new(pk);

        let merged = merge_addr(&existing, &incoming);
        assert!(merged.ip_addrs().any(|a| a == &ip));
        Ok(())
    }

    #[test]
    fn merge_node_prefers_ip_addr_even_if_older() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let existing_ip: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let existing_addr = EndpointAddr::from_parts(pk, [TransportAddr::Ip(existing_ip)]);
        let incoming_addr = EndpointAddr::new(pk);

        let mut existing = node_with_addr(existing_addr, 100);
        existing.node_id = pk;
        let mut incoming = node_with_addr(incoming_addr, 200);
        incoming.node_id = pk;

        let (merged, _) = merge_node(Some(&existing), &incoming);
        assert!(merged.addr.ip_addrs().any(|a| a == &existing_ip));
    }

    #[test]
    fn ids_to_remove_for_duplicate_domains_removes_older() {
        let mut rng = rand::rng();
        let pk1 = SecretKey::generate(&mut rng).public();
        let pk2 = SecretKey::generate(&mut rng).public();

        let n1 = Node {
            node_id: pk1,
            invitor: pk1,
            addr: EndpointAddr::new(pk1),
            domain: "dup".to_string(),
            services: BTreeMap::new(),
            last_heartbeat: 10,
        };
        let n2 = Node {
            node_id: pk2,
            invitor: pk2,
            addr: EndpointAddr::new(pk2),
            domain: "dup".to_string(),
            services: BTreeMap::new(),
            last_heartbeat: 20,
        };

        let mut ids = ids_to_remove_for_duplicate_domains(&[n1, n2]);
        ids.sort();
        assert_eq!(ids, vec![pk1]);
    }
}
