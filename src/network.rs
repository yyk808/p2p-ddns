use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use ed25519::Signature;
use futures_lite::StreamExt;
use iroh::{
    Endpoint, NodeAddr, NodeId, PublicKey, SecretKey,
    discovery::{DiscoveryItem, Lagged},
    protocol::Router,
};
use iroh_gossip::{
    ALPN,
    net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender, Message as IrohMessage},
    proto::TopicId,
};
use serde::{Deserialize, Serialize};

use crate::{
    storage::Storage,
    utils::{Args, Ticket},
};

#[derive(Debug, Serialize, Deserialize)]
enum Message {
    AboutMe {
        alias: String,
        services: BTreeMap<String, u32>,
        invitor: NodeId,
    },
    SyncRequest {
        nodes: Vec<Node>,
    },
    SyncResponse {
        nodes: Vec<Node>,
    },
    Introduce {
        invited: NodeId,
    },
    Heartbeat,
    Left,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedMessage {
    from: NodeId,
    data: Bytes,
    signature: Signature,
    timestamp: u64,
}

impl SignedMessage {
    pub fn decode_and_verify(ctx: Context, bytes: &[u8]) -> Result<(PublicKey, Message, bool)> {
        let signed_message: Self = postcard::from_bytes(bytes)?;
        let key: PublicKey = signed_message.from;

        key.verify(&signed_message.data, &signed_message.signature)?;
        let message: Message = postcard::from_bytes(&signed_message.data)?;
        let pass = ctx.is_node_trusted(&key);
        Ok((signed_message.from, message, pass))
    }

    pub fn sign_and_encode(secret_key: &SecretKey, message: Message) -> Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        let signature = secret_key.sign(&data);
        let from: PublicKey = secret_key.public();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let signed_message = Self {
            from,
            data,
            signature,
            timestamp,
        };
        let encoded = postcard::to_stdvec(&signed_message)?;
        Ok(encoded.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub node_id: NodeId,
    pub invitor: NodeId,
    addr: NodeAddr,
    alias: String,
    services: BTreeMap<String, u32>,
    last_heartbeat: u64,
}

#[derive(Debug, Clone)]
pub struct Auth {
    pub introducer: NodeId,
    pub introduced: bool,
    pub node: Option<Box<Node>>,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct Context {
    pub handle: Endpoint,
    pub storage: Storage,
    pub router: Router,
    pub gossip: Gossip,
    pub topic: TopicId,
    pub nodes: DashMap<NodeId, Node>,
    pub me: Arc<Node>,
    pub lag_happend: Arc<AtomicBool>,
    pub sender: GossipSender,
    pub pending_auth: DashMap<NodeId, Auth>,
}

impl Hash for Node {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.node_id.hash(state);
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
    }
}

impl Eq for Node {}

impl Hash for Auth {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.introducer.hash(state);
    }
}

impl PartialEq for Auth {
    fn eq(&self, other: &Self) -> bool {
        self.introducer == other.introducer
    }
}

impl Eq for Auth {}

pub async fn init_network(args: &Args, storage: Storage) -> Result<(Context, GossipReceiver)> {
    let sk = SecretKey::generate(rand::rngs::OsRng);
    let pk = sk.public();

    // TODO: distinguish daemon and client mode
    // TODO: dynamic ALPN name
    let endpoint = Endpoint::builder()
        .relay_mode(iroh::RelayMode::Disabled)
        .secret_key(sk)
        .discovery_local_network()
        .discovery_dht()
        .bind()
        .await?;

    let nodes = storage.load_nodes()?;
    nodes.iter().for_each(|node| {
        endpoint.add_node_addr(NodeAddr::from(node.addr.clone()));
    });

    let ticket = if args.primary {
        let topic = TopicId::from_bytes(rand::random());
        let rnum = rand::random::<[u8; 32]>().to_vec();
        let me = endpoint.node_addr().await?;
        Ticket {
            topic,
            rnum,
            addr: me,
        }
    } else {
        Ticket::from_str(&args.ticket.clone().unwrap())?
    };

    let gossip = Gossip::builder().spawn(endpoint.clone()).await?;
    let router = Router::builder(endpoint)
        .accept(ALPN, gossip.clone())
        .spawn()
        .await?;

    let bootstrap = nodes.iter().map(|node| node.addr.node_id.clone()).collect();
    let (sender, receiver) = gossip
        .subscribe_and_join(ticket.topic, bootstrap)
        .await?
        .split();

    let context = todo!();

    Ok(context)
}

impl Context {
    pub async fn run(&self, mut receiver: GossipReceiver) -> Result<()> {
        let mut discovery_stream = self.handle.discovery_stream();
        let conn = self.handle.accept().await;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    break;
                },
                evt = receiver.try_next() => {
                    self.process_gossip(evt.map_err(|e| anyhow::anyhow!(e))).await;

                }
                item = discovery_stream.next() => {
                    self.process_discovery(item).await;
                },
                Some(incoming) = self.handle.accept() => {
                    let connecting = match incoming.accept() {
                        Ok(connecting) => connecting,
                        Err(err) => {
                            log::warn!("incoming connection failed: {err:#}");
                            // we can carry on in these cases:
                            // this can be caused by retransmitted datagrams
                            continue;
                        }
                    };
                    let connection = connecting.await?;

                }
            }
        }

        self.router.shutdown().await
    }

    async fn process_gossip(&self, evt: Result<Option<Event>>) {
        match evt {
            Ok(Some(evt)) => match evt {
                Event::Gossip(gossip_event) => match gossip_event {
                    GossipEvent::Joined(items) => todo!(),
                    GossipEvent::NeighborUp(public_key) => todo!(),
                    GossipEvent::NeighborDown(public_key) => todo!(),
                    GossipEvent::Received(message) => self.process_message(message).await,
                },
                Event::Lagged => {
                    self.lag_happend
                        .store(true, std::sync::atomic::Ordering::Release);
                }
            },
            Err(e) => log::error!("Error processing gossip event: {:?}", e),
            _ => {}
        }
    }

    async fn process_discovery(&self, item: Option<Result<DiscoveryItem, Lagged>>) {
        if let Some(Ok(addr)) = item {
            todo!()
        }
    }

    async fn process_message(&self, message: IrohMessage) {
        if let Ok((id, msg, passed)) =
            SignedMessage::decode_and_verify(self.clone(), &message.content)
        {
            log::debug!("Received message from {:?}", id);
            log::debug!("Message: {:?}", msg);
            match msg {
                Message::AboutMe {
                    alias,
                    services,
                    invitor,
                } => {
                    let addr = if let Some(info) = self.handle.remote_info(id) {
                        // We have no relay for sure.
                        NodeAddr::from_parts(
                            id,
                            None,
                            info.addrs
                                .iter()
                                .map(|addr| addr.addr)
                                .collect::<Vec<SocketAddr>>(),
                        )
                    } else {
                        log::error!("No remote info for node: {:?}", id);
                        return;
                    };

                    let node = Node {
                        node_id: id,
                        invitor,
                        addr,
                        alias,
                        services,
                        last_heartbeat: 0,
                    };

                    if self.pending_auth.contains_key(&id) {
                        let auth = self.pending_auth.get(&id).unwrap();
                        if auth.introduced {
                            // We already reveived a message from this node, but it was not introduced.
                            // Simply update the information.
                            self.pending_auth.alter(&id, |_, auth| Auth {
                                introducer: auth.introducer,
                                introduced: false,
                                node: auth.node,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            });
                        } else {
                            // This node has been introduced, we can trust it now.
                            self.pending_auth.remove(&id);
                            self.nodes.insert(id, node);
                        }
                    } else {
                        // This node has not been introduced yet.
                        let auth = Auth {
                            introducer: id,
                            introduced: false,
                            node: Box::new(node).into(),
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        };
                        self.pending_auth.insert(id, auth);
                    }
                }
                Message::Introduce { invited } => {
                    if !passed {
                        log::error!("Received untrusted Introduce message from {:?}", id);
                        return;
                    }
                    log::info!("Received Introduce message from {:?}", id);
                    if self.pending_auth.contains_key(&id) {
                        let auth = self.pending_auth.get(&id).unwrap();
                        if auth.introduced {
                            self.pending_auth.alter(&id, |_, auth| Auth {
                                introducer: auth.introducer,
                                introduced: true,
                                node: auth.node,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            });
                        } else {
                            // This node has sent 'AboutMe' message before.
                            assert!(auth.node.is_some());
                            if let Some((id, auth)) = self.pending_auth.remove(&id) {
                                let node = auth.node.unwrap();
                                self.nodes.insert(id, *node);
                            }
                        }
                    } else {
                        let auth = Auth {
                            introducer: id,
                            introduced: true,
                            node: None,
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        };
                        self.pending_auth.insert(invited, auth);
                    }
                }
                Message::Heartbeat => {
                    if !passed {
                        log::error!("Received untrusted Heartbeat message from {:?}", id);
                        return;
                    }

                    if let Some(mut node) = self.nodes.get_mut(&id) {
                        node.last_heartbeat = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                    }
                }
                Message::Left => {
                    if !passed {
                        log::error!("Received untrusted Left message from {:?}", id);
                        return;
                    }

                    if let Some((id, _)) = self.nodes.remove(&id) {
                        log::info!("Node {} left the chat", id);
                    }
                }
                Message::SyncRequest { nodes } => {
                    nodes.iter().for_each(|node| {
                        let target = self.nodes.get(&node.node_id);
                        if target
                            .is_some_and(|inner| inner.last_heartbeat + 60 < node.last_heartbeat)
                        {
                            self.nodes.insert(node.node_id, node.clone());
                        }
                    });

                    let nodes = self
                        .nodes
                        .iter()
                        .map(|t| t.value().clone())
                        .collect::<Vec<_>>();

                    let message = Message::SyncResponse { nodes };
                    self.send_message_to(&id, message).await.unwrap();
                }
                Message::SyncResponse { nodes } => {
                    nodes.iter().for_each(|node| {
                        let target = self.nodes.get(&node.node_id);
                        if target.is_none() || target.unwrap().last_heartbeat < node.last_heartbeat
                        {
                            self.nodes.insert(node.node_id, node.clone());
                        }
                    });
                }

                #[allow(unreachable_patterns)]
                _ => log::warn!("Unknown message received"),
            }
        }
    }

    pub async fn broadcast_message(&self, message: Message) -> Result<()> {
        let bm = SignedMessage::sign_and_encode(self.handle.secret_key(), message)?;
        self.sender.broadcast(bm).await?;
        Ok(())
    }

    pub async fn broadcast_neighbor_message(&self, message: Message) -> Result<()> {
        let bm = SignedMessage::sign_and_encode(self.handle.secret_key(), message)?;
        self.sender.broadcast_neighbors(bm).await?;
        Ok(())
    }

    pub async fn send_message_to(&self, id: &NodeId, message: Message) -> Result<()> {
        if let Some(info) = self.handle.remote_info(*id) {
            let addr = NodeAddr::from(info);
            match self.handle.connect(addr, ALPN).await {
                Ok(conn) => {
                    let bm = SignedMessage::sign_and_encode(self.handle.secret_key(), message)?;
                    let mut tun = conn.open_uni().await?;
                    tun.write_all(bm.as_ref()).await?;
                    Ok(())
                }
                Err(e) => Err(anyhow::anyhow!("Failed to connect to {:?}: {:?}", id, e)),
            }
        } else {
            Err(anyhow::anyhow!(
                "Trying to send message to unknown peer {:?}",
                id
            ))
        }
    }

    pub fn is_node_trusted(&self, id: &NodeId) -> bool {
        self.nodes.contains_key(id)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    impl Node {
        pub fn random_node() -> Self {
            let sk = SecretKey::generate(rand::rngs::OsRng);
            let pk = sk.public();

            Self {
                node_id: pk,
                invitor: pk,
                alias: String::default(),
                services: BTreeMap::new(),
                last_heartbeat: 0,
                addr: NodeAddr::from_parts(pk, None, vec![]),
            }
        }
    }

    #[test]
    fn test_network() {
        todo!()
    }
}
