use std::collections::HashMap;
use std::net::SocketAddr;

use iroh::{EndpointAddr, EndpointId, TransportAddr};

use crate::domain::node::Node;

pub fn has_ip_addr(addr: &EndpointAddr) -> bool {
    addr.ip_addrs().next().is_some()
}

pub fn merge_addr(existing: &EndpointAddr, incoming: &EndpointAddr) -> EndpointAddr {
    if existing.id != incoming.id {
        return incoming.clone();
    }

    let mut ips = Vec::<SocketAddr>::new();
    for addr in existing.ip_addrs() {
        let addr = *addr;
        if !ips.contains(&addr) {
            ips.push(addr);
        }
    }
    for addr in incoming.ip_addrs() {
        let addr = *addr;
        if !ips.contains(&addr) {
            ips.push(addr);
        }
    }

    if ips.is_empty() {
        return incoming.clone();
    }

    EndpointAddr::from_parts(existing.id, ips.into_iter().map(TransportAddr::Ip))
}

pub fn merge_node(existing: Option<&Node>, incoming: &Node) -> (Node, bool) {
    match existing {
        None => (incoming.clone(), true),
        Some(existing) => {
            let should_take_incoming = incoming.last_heartbeat > existing.last_heartbeat;
            let services = if should_take_incoming
                || (incoming.last_heartbeat == existing.last_heartbeat
                    && !incoming.services.is_empty())
            {
                incoming.services.clone()
            } else {
                existing.services.clone()
            };
            let addr = if should_take_incoming && has_ip_addr(&incoming.addr) {
                incoming.addr.clone()
            } else {
                merge_addr(&existing.addr, &incoming.addr)
            };

            let merged = if should_take_incoming {
                Node {
                    addr,
                    services,
                    ..incoming.clone()
                }
            } else {
                Node {
                    addr,
                    services,
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
    fn merge_addr_unions_ip_addrs() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let existing = EndpointAddr::from_parts(pk, [TransportAddr::Ip(a)]);
        let incoming = EndpointAddr::from_parts(pk, [TransportAddr::Ip(b)]);

        let merged = merge_addr(&existing, &incoming);
        let mut ips = merged.ip_addrs().copied().collect::<Vec<_>>();
        ips.sort();
        assert_eq!(ips, vec![a, b]);
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
    fn merge_node_replaces_prior_dhcp_ip_when_newer_update_has_ip() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let old_ip: SocketAddr = "10.0.0.20:7777".parse().unwrap();
        let new_ip: SocketAddr = "10.0.0.37:7777".parse().unwrap();

        let mut existing = node_with_addr(
            EndpointAddr::from_parts(pk, [TransportAddr::Ip(old_ip)]),
            10,
        );
        existing.node_id = pk;

        let mut incoming = existing.clone();
        incoming.addr = EndpointAddr::from_parts(pk, [TransportAddr::Ip(new_ip)]);
        incoming.last_heartbeat = 20;

        let (merged, _) = merge_node(Some(&existing), &incoming);
        let ips = merged.addr.ip_addrs().copied().collect::<Vec<_>>();

        assert!(
            !ips.contains(&old_ip),
            "newer DHCP address update should replace the old IP instead of keeping it"
        );
        assert!(ips.contains(&new_ip));
    }

    #[test]
    fn merge_node_accepts_same_second_service_update() {
        let mut rng = rand::rng();
        let pk = SecretKey::generate(&mut rng).public();

        let mut existing = node_with_addr(EndpointAddr::new(pk), 100);
        existing.node_id = pk;

        let mut incoming = existing.clone();
        incoming
            .services
            .insert("openclaw-agent".to_string(), 39092);

        let (merged, _) = merge_node(Some(&existing), &incoming);

        assert_eq!(merged.services.get("openclaw-agent"), Some(&39092));
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
