use iroh::EndpointAddr;

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
}
