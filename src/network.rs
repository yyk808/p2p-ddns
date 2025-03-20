use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::{BuildHasherDefault, DefaultHasher, Hash, Hasher},
    iter::Map,
    net::SocketAddr,
    str::FromStr,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::Result;
use bytes::Bytes;
use clap::Arg;
use dashmap::DashSet;
use ed25519::Signature;
use futures_lite::StreamExt;
use iroh::{
    discovery::{pkarr::dht::DhtDiscovery, DiscoveryItem, Lagged}, endpoint::{DirectAddr, RemoteInfo}, node_info::UserData, protocol::Router, Endpoint, NodeAddr, NodeId, PublicKey, SecretKey
};
use iroh_gossip::{
    net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender, Message as IrohMessage}, proto::{Config, TopicId}, ALPN
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;

use crate::{storage::Storage, utils::{Args, Ticket}};

#[derive(Debug, Serialize, Deserialize)]
enum Message {
    AboutMe {
        alias: String,
        services: BTreeMap<String, u32>,
        invitor: Option<NodeId>,
        client: bool,
    },
    ReInvite {
        me: NodeId,
    },
    Introduce {  },
    Heartbeat,
    Left,
}

impl Message {
    pub fn into_signed(self, ctx: Context) -> Result<Bytes> {
        SignedMessage::sign_and_encode(ctx.handle.secret_key(), self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedMessage {
    from: NodeId,
    data: Bytes,
    signature: Signature,
    timestamp: u128,
}

impl SignedMessage {
    pub fn decode_and_verify(bytes: &[u8]) -> Result<(PublicKey, Message)> {
        let signed_message: Self = postcard::from_bytes(bytes)?;
        let key: PublicKey = signed_message.from;
        key.verify(&signed_message.data, &signed_message.signature)?;
        let message: Message = postcard::from_bytes(&signed_message.data)?;
        Ok((signed_message.from, message))
    }

    pub fn sign_and_encode(secret_key: &SecretKey, message: Message) -> Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        let signature = secret_key.sign(&data);
        let from: PublicKey = secret_key.public();
        let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
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
    pub invitor: Option<NodeId>,
    addr: NodeAddr,
    alias: String,
    services: BTreeMap<String, u32>,
    trusted: bool,
    last_heartbeat: u64,
}

#[derive(Debug, Clone)]
pub struct Context {
    pub handle: Endpoint,
    pub storage: Storage,
    pub router: Router,
    pub gossip: Gossip,
    pub topic: TopicId,
    pub nodes: Arc<DashSet<Node>>,
    pub me: Arc<Node>,
    pub lag_happend: Arc<AtomicBool>,
    pub sender: GossipSender,
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

pub async fn init_network(args: &Args, storage: Storage) -> Result<(Context, GossipReceiver)> {
    let sk = SecretKey::generate(rand::rngs::OsRng);
    let pk = sk.public();

    // TODO: distinguish daemon and client mode
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
    let (sender, mut receiver) = gossip.subscribe_and_join(ticket.topic, bootstrap).await?.split();

    let context = todo!();

    Ok(context)
}

impl Context {
    pub async fn run(&self, mut receiver: GossipReceiver) -> Result<()> {
        let mut discovery_stream = self.handle.discovery_stream();

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
                }
            }
        }

        self.router.shutdown().await
    }

    async fn process_gossip(&self, evt: Result<Option<Event>>) {
        match evt {
            Ok(Some(evt)) => {
                match evt {
                    Event::Gossip(gossip_event) => {
                        match gossip_event {
                            GossipEvent::Joined(items) => todo!(),
                            GossipEvent::NeighborUp(public_key) => todo!(),
                            GossipEvent::NeighborDown(public_key) => todo!(),
                            GossipEvent::Received(message) => self.process_message(message).await,
                        }
                    },
                    Event::Lagged => {
                        self.lag_happend.store(true, std::sync::atomic::Ordering::Release);
                    }
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
        if let Ok((id, msg)) = SignedMessage::decode_and_verify(&message.content) {
            match msg {
                Message::AboutMe { alias, services, invitor, client } => {
                    let addr = if let Some(info) = self.handle.remote_info(id) {
                        // We have no relay for sure.
                        NodeAddr::from_parts(id, None, info.addrs.iter().map(|addr| addr.addr ).collect::<Vec<SocketAddr>>())
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
                        trusted: false,
                        last_heartbeat: 0,
                    };

                    self.nodes.insert(node.clone());


                },
                Message::ReInvite { me } => todo!(),
                Message::Introduce {  } => todo!(),
                Message::Heartbeat => todo!(),
                Message::Left => todo!(),
            }
        }
    }

    pub async fn broadcast_message(&self, message: Message) -> Result<()> {
        let bm = Message::into_signed(message, self.clone())?;
        self.sender.broadcast(bm).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tempfile::tempfile;

    impl Node {
        pub fn random_node() -> Self {
            let sk = SecretKey::generate(rand::rngs::OsRng);
            let pk = sk.public();

            Self {
                node_id: pk,
                invitor: Some(NodeId::from(pk)),
                alias: String::default(),
                services: BTreeMap::new(),
                trusted: false,
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
