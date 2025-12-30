use core::fmt;
use std::{str::FromStr, sync::Arc};

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use iroh::EndpointAddr;
use iroh_gossip::TopicId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{domain::merge, domain::node::Node, util::time_now};

#[derive(Debug, Clone)]
pub struct Ticket {
    inner: Arc<RwLock<TicketInner>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TicketInner {
    pub topic: TopicId,
    pub rnum: Vec<u8>,
    pub invitor: Node,
}

impl Ticket {
    pub fn new(topic: Option<TopicId>, node: Node) -> Self {
        let rnum = rand::random::<[u8; 32]>().to_vec();
        let topic = topic.unwrap_or_else(|| TopicId::from_bytes(rand::random()));
        Self {
            inner: Arc::new(RwLock::new(TicketInner {
                topic,
                rnum,
                invitor: node,
            })),
        }
    }

    pub fn from_parts(topic: TopicId, rnum: Vec<u8>, invitor: Node) -> Self {
        Self {
            inner: Arc::new(RwLock::new(TicketInner {
                topic,
                rnum,
                invitor,
            })),
        }
    }

    pub fn topic(&self) -> TopicId {
        self.inner.read().topic
    }

    pub fn rnum(&self) -> Vec<u8> {
        self.inner.read().rnum.clone()
    }

    pub fn validate(&self, topic: TopicId, rnum: impl AsRef<[u8]>) -> bool {
        self.inner.read().topic == topic && self.inner.read().rnum == rnum.as_ref()
    }

    pub fn flatten(&self) -> (TopicId, Vec<u8>, Node) {
        let inner = self.inner.read();
        (inner.topic, inner.rnum.clone(), inner.invitor.clone())
    }

    pub fn refresh_with(&self, mut invitor: Node, addr: EndpointAddr, now: u64) {
        let mut inner = self.inner.write();
        inner.rnum = rand::random::<[u8; 32]>().to_vec();
        invitor.addr = merge::merge_addr(&inner.invitor.addr, &addr);
        invitor.last_heartbeat = now;
        inner.invitor = invitor;
    }

    pub fn refresh_from(&self, invitor: Node, addr: EndpointAddr) {
        self.refresh_with(invitor, addr, time_now());
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(debug_assertions)]
        log::debug!("Displaying Ticket: {:?}", self.inner);

        let inner = self.inner.read();
        match postcard::to_stdvec(&*inner) {
            Ok(text) => {
                let text = STANDARD_NO_PAD.encode(text);
                write!(f, "{}", text)
            }
            Err(_) => write!(f, "<ticket-encode-error>"),
        }
    }
}

impl FromStr for Ticket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = STANDARD_NO_PAD.decode(s)?;
        let inner: Result<TicketInner> =
            postcard::from_bytes(&bytes).map_err(|e| anyhow::anyhow!(e));

        #[cfg(debug_assertions)]
        log::debug!("Loaded Ticket from str: {:?}", inner);

        inner.map(|inner| Self {
            inner: Arc::new(RwLock::new(inner)),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use anyhow::Result;
    use iroh::{SecretKey, TransportAddr};

    use super::*;

    #[test]
    fn ticket_roundtrip_display_fromstr() -> Result<()> {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let node = Node {
            node_id: pk,
            invitor: pk,
            addr: iroh::EndpointAddr::new(pk),
            domain: "node".to_string(),
            services: Default::default(),
            last_heartbeat: 123,
        };

        let ticket = Ticket::new(None, node);
        let encoded = ticket.to_string();
        let decoded: Ticket = encoded.parse()?;

        let (topic_a, rnum_a, invitor_a) = ticket.flatten();
        let (topic_b, rnum_b, invitor_b) = decoded.flatten();
        assert_eq!(topic_a, topic_b);
        assert_eq!(rnum_a, rnum_b);
        assert_eq!(invitor_a.node_id, invitor_b.node_id);
        Ok(())
    }

    #[test]
    fn ticket_refresh_with_updates_rnum_and_invitor() {
        let mut rng = rand::rng();
        let sk = iroh::SecretKey::generate(&mut rng);
        let pk = sk.public();

        let node = Node {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::new(pk),
            domain: "node".to_string(),
            services: Default::default(),
            last_heartbeat: 0,
        };

        let ticket = Ticket::new(None, node.clone());
        let (topic_before, rnum_before, invitor_before) = ticket.flatten();
        assert_eq!(invitor_before.last_heartbeat, 0);

        let new_addr: SocketAddr = "[2001:db8::10]:1234".parse().unwrap();
        let new_addr = EndpointAddr::from_parts(pk, [iroh::TransportAddr::Ip(new_addr)]);
        ticket.refresh_with(node, new_addr.clone(), 42);

        let (topic_after, rnum_after, invitor_after) = ticket.flatten();
        assert_eq!(topic_before, topic_after);
        assert_ne!(rnum_before, rnum_after);
        assert_eq!(invitor_after.addr, new_addr);
        assert_eq!(invitor_after.last_heartbeat, 42);
    }

    #[test]
    fn ticket_refresh_with_merges_invitor_addrs() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let a: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:2222".parse().unwrap();

        let node = Node {
            node_id: pk,
            invitor: pk,
            addr: EndpointAddr::from_parts(pk, [TransportAddr::Ip(a)]),
            domain: "node".to_string(),
            services: Default::default(),
            last_heartbeat: 0,
        };

        let ticket = Ticket::new(None, node.clone());
        ticket.refresh_with(
            node,
            EndpointAddr::from_parts(pk, [TransportAddr::Ip(b)]),
            1,
        );

        let (_, _, invitor) = ticket.flatten();
        let mut ips = invitor.addr.ip_addrs().copied().collect::<Vec<_>>();
        ips.sort();
        assert_eq!(ips, vec![a, b]);
    }
}
