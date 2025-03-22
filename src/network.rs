use std::{cmp::max, collections::BTreeMap, hash::Hash, net::SocketAddr, str::FromStr, sync::Arc};

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use ed25519::Signature;
use futures_lite::StreamExt;
use iroh::{
    Endpoint, NodeAddr, NodeId, PublicKey, SecretKey,
    discovery::{
        ConcurrentDiscovery, local_swarm_discovery::LocalSwarmDiscovery,
        static_provider::StaticProvider,
    },
    node_info::{NodeData, NodeInfo, UserData},
    protocol::Router,
};
use iroh_gossip::{
    ALPN,
    net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender, Message as IrohMessage},
    proto::TopicId,
};
use rand::{
    Rng,
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use serde::{Deserialize, Serialize};

use crate::{
    storage::Storage,
    utils::{CliArgs, Ticket},
};

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
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
        let passed = ctx.is_node_trusted(&key)
            && signed_message.timestamp - 10
                < std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
        Ok((signed_message.from, message, passed))
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
    pub(crate) addr: NodeAddr,
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

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Context {
    pub handle: Endpoint,
    pub storage: Storage,
    pub router: Router,
    pub gossip: Gossip,
    pub ticket: Ticket,
    pub nodes: DashMap<NodeId, Node>,
    pub me: Arc<Node>,
    pub sender: GossipSender,
    pub args: CliArgs,
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

pub async fn init_network(args: CliArgs, storage: Storage) -> Result<(Context, GossipReceiver)> {
    let nodes = storage.load_nodes()?;

    // Try to load the secret key from storage, if not found, generate a new one.
    // The public key is used as the node ID to be acknowledged by other nodes.
    let (pk, sk) = storage.load_secret()?.unwrap_or_else(|| {
        let sk = SecretKey::generate(rand::rngs::OsRng);
        let pk = sk.public();
        storage.save_secret(sk.clone()).unwrap();
        (pk, sk)
    });

    // Set up bootstrap nodes with ticket and storage
    let arg_ticket = Ticket::from_str(args.ticket.as_deref().unwrap_or("".into()));
    let invitor_addr = arg_ticket.as_ref().map(|t| t.load_addr());
    let invitor = match invitor_addr.as_ref() {
        Ok(addr) => addr.node_id,
        Err(_) => pk.clone(),
    };

    let mut discoveries = ConcurrentDiscovery::empty();
    let sp = StaticProvider::new();
    if let Ok(addr) = invitor_addr {
        sp.add_node_info(NodeInfo::from_parts(addr.node_id, NodeData::from(addr)));
    }
    nodes.iter().for_each(|node| {
        let info = NodeInfo {
            node_id: node.node_id,
            data: NodeData::from(node.addr.clone()),
        };
        sp.add_node_info(info);
    });
    discoveries.add(sp);

    if args.daemon {
        let local_discovery = LocalSwarmDiscovery::new(pk).unwrap();
        discoveries.add(local_discovery);
    }

    // TODO: dynamic ALPN name
    // endpoint-protocol(gossip)-router are iroh components
    let endpoint = Endpoint::builder()
        .relay_mode(iroh::RelayMode::Disabled)
        .secret_key(sk)
        .add_discovery(|_| Some(discoveries))
        .bind()
        .await?;
    let gossip = Gossip::builder().spawn(endpoint.clone()).await?;
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, gossip.clone())
        .spawn()
        .await?;
    let me = endpoint.node_addr().await?;

    // Generate a ticket for ourself.
    let ticket = match arg_ticket {
        Ok(ticket) => Ticket::new(Some(ticket.topic()), me.clone()),
        Err(_) => Ticket::new(None, me.clone()),
    };

    let bootstrap = nodes.iter().map(|node| node.addr.node_id).collect();

    let (sender, receiver) = if args.primary {
        gossip.subscribe(ticket.topic(), bootstrap)?.split()
    } else {
        gossip
            .subscribe_and_join(ticket.topic(), bootstrap)
            .await
            .map_err(|e| anyhow::anyhow!("Cannot connect to any existing node: {}", e))?
            .split()
    };

    let alias = args.alias.clone().unwrap_or(
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect(),
    );

    // for now, this takes no effect since we don't handle discovery events manually.
    endpoint.set_user_data_for_discovery(
        args.alias
            .clone()
            .map(|alias| UserData::from_str(alias.as_str()).unwrap()),
    );

    let me = Node {
        node_id: pk,
        invitor,
        addr: me,
        alias,
        services: Default::default(), // reserved
        last_heartbeat: 0,
    };

    let context = Context {
        handle: endpoint,
        storage,
        router,
        gossip,
        ticket,
        nodes: DashMap::new(),
        me: Arc::new(me),
        sender,
        args,
        pending_auth: DashMap::new(),
    };

    Ok((context, receiver))
}

impl Context {
    pub async fn run(&self, mut receiver: GossipReceiver) {
        let mut cron_jobs = tokio::time::interval(std::time::Duration::from_secs(30));

        // before join the loop, we still need to broadcast some message to bootstrap ourself.
        if self.args.daemon {
            let about_me = Message::AboutMe {
                alias: self.me.alias.clone(),
                services: self.me.services.clone(),
                invitor: self.me.invitor,
            };
            if self.broadcast_message(about_me).await.is_err() && !self.args.primary {
                log::error!("Failed to broadcast AboutMe message to bootstrap the network");
            }
        }

        // Errors are expected if we are the first node in network.
        let sync_req = Message::SyncRequest {
            nodes: Default::default(),
        };
        let _ = self.broadcast_neighbor_message(sync_req).await;

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    log::info!("Shutting down...");
                    self.graceful_shutdown().await;
                    break;
                },
                _ = cron_jobs.tick() => {
                    if self.args.daemon {
                        let _ = self.broadcast_message(Message::Heartbeat).await;
                    }

                    self.cleanup().await;
                    self.update_nodes().await;
                    if let Err(e) = self.save().await {
                        log::error!("Failed to save nodes to storage: {:?}", e);
                    }
                },
                evt = receiver.try_next() => {
                    self.process_gossip(evt.map_err(|e| anyhow::anyhow!(e))).await;
                }
            }
        }
    }

    pub async fn graceful_shutdown(&self) {
        let _ = self.broadcast_message(Message::Left).await;
        let _ = self.save().await;
        let _ = self.router.shutdown().await;
        self.handle.close().await;
    }

    pub async fn save(&self) -> Result<()> {
        self.nodes.remove(&self.me.node_id);

        log::info!("Saving {} nodes to storage", self.nodes.len());
        let nodes = self
            .nodes
            .iter()
            .map(|it| it.value().clone())
            .collect::<Vec<_>>();
        self.storage.batch_save_nodes(nodes.into_iter())?;

        Ok(())
    }

    pub async fn cleanup(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.pending_auth
            .retain(|_, auth| now - auth.timestamp < 60 * 5);

        // Clean up nodes that have the same alias name.
        // Find nodes with duplicate aliases, keeping only the most recent one
        let mut by_alias: std::collections::HashMap<String, (NodeId, u64)> =
            std::collections::HashMap::new();
        for pair in self.nodes.iter() {
            let node = pair.value();
            by_alias
                .entry(node.alias.clone())
                .and_modify(|(id, heartbeat)| {
                    if node.last_heartbeat > *heartbeat {
                        *id = node.node_id;
                        *heartbeat = node.last_heartbeat;
                    }
                })
                .or_insert((node.node_id, node.last_heartbeat));
        }

        // Remove nodes that have the same alias but aren't the most recent
        for pair in self.nodes.iter() {
            let node = pair.value();
            if let Some((best_id, _)) = by_alias.get(&node.alias) {
                if *best_id != node.node_id {
                    self.nodes.remove(&node.node_id);
                }
            }
        }
    }

    pub async fn update_nodes(&self) {
        for info in self.handle.remote_info_iter() {
            let id = info.node_id;

            // we don't care the node not in self.nodes, since it's authenticated.
            if self.nodes.contains_key(&id) {
                self.nodes.alter(&id, |_, mut node| {
                    // update heartbeat timestamp
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let iroh_timestamp = now - info.last_used.map_or(0, |t| t.as_secs());
                    let local_timestamp = node.last_heartbeat;
                    node.last_heartbeat = max(iroh_timestamp, local_timestamp);

                    // update ip addresses
                    info.addrs.iter().for_each(|addr| {
                        if !node.addr.direct_addresses.contains(&addr.addr) {
                            node.addr.direct_addresses.insert(addr.addr);
                        }
                    });

                    node
                });
            }
        }

        let nodes = self
            .nodes
            .iter()
            .map(|it| it.value().clone())
            .collect::<Vec<_>>();
        let _ = self
            .broadcast_neighbor_message(Message::SyncRequest { nodes })
            .await;
    }

    async fn process_gossip(&self, evt: Result<Option<Event>>) {
        match evt {
            Ok(Some(evt)) => match evt {
                Event::Gossip(gossip_event) => match gossip_event {
                    GossipEvent::NeighborDown(public_key) => {
                        self.nodes.remove(&public_key);
                        self.pending_auth.remove(&public_key);
                    }
                    GossipEvent::Received(message) => self.process_message(message).await,
                    _ => {}
                },
                Event::Lagged => log::warn!("Gossip network is lagged"),
            },
            Err(e) => log::error!("Error processing gossip event: {:?}", e),
            _ => {}
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
                    if passed {
                        nodes.iter().for_each(|node| {
                            let target = self.nodes.get(&node.node_id);
                            if target.is_some_and(|inner| {
                                inner.last_heartbeat + 60 < node.last_heartbeat
                            }) {
                                self.nodes.insert(node.node_id, node.clone());
                            }
                        });
                    }

                    let nodes = self
                        .nodes
                        .iter()
                        .map(|t| t.value().clone())
                        .collect::<Vec<_>>();

                    let message = Message::SyncResponse { nodes };
                    self.send_message_to(&id, message).await.unwrap();
                }
                Message::SyncResponse { nodes } => {
                    // A message from a trusted node is always valid.
                    // Or if we are a client, we simply trust everything.
                    if !self.args.daemon || (self.args.daemon && passed) {
                        nodes.iter().for_each(|node| {
                            let target = self.nodes.get(&node.node_id);
                            if target.is_none()
                                || target.unwrap().last_heartbeat < node.last_heartbeat
                            {
                                self.nodes.insert(node.node_id, node.clone());
                            }
                        });
                    }
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

    #[allow(dead_code)]
    pub async fn broadcast_neighbor_message(&self, message: Message) -> Result<()> {
        let bm = SignedMessage::sign_and_encode(self.handle.secret_key(), message)?;
        self.sender.broadcast_neighbors(bm).await?;
        Ok(())
    }

    pub async fn send_message_to(&self, id: &NodeId, message: Message) -> Result<()> {
        if id == &self.me.node_id {
            return Ok(());
        }

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

    // #[test]
    // fn test_signed_message_decode_and_verify() {
    //     // 创建测试上下文
    //     let ctx = Context::default();

    //     // 创建测试消息
    //     let message = Message::AboutMe {
    //         alias: "Test Alias".to_string(),
    //         services: BTreeMap::new(),
    //         invitor: NodeId::default(),
    //     };

    //     // 对消息进行签名和编码
    //     let encoded_message =
    //         SignedMessage::sign_and_encode(&ctx.handle.secret_key(), message).unwrap();

    //     // 解码并验证消息
    //     let (decoded_key, decoded_message, pass) =
    //         SignedMessage::decode_and_verify(ctx, &encoded_message).unwrap();

    //     // 验证解码结果
    //     assert_eq!(decoded_message, message);
    //     assert!(pass);
    // }

    // #[test]
    // fn test_signed_message_sign_and_encode() {
    //     // 创建测试消息
    //     let message = Message::AboutMe {
    //         alias: "Test Alias".to_string(),
    //         services: BTreeMap::new(),
    //         invitor: NodeId::default(),
    //     };

    //     // 对消息进行签名和编码
    //     let encoded_message =
    //         SignedMessage::sign_and_encode(&ctx.handle.secret_key(), message).unwrap();

    //     // 验证编码结果
    //     assert!(!encoded_message.is_empty());
    // }

    // #[test]
    // fn test_init_network() {
    //     // 创建测试参数
    //     let args = Args::default();

    //     // 创建测试存储
    //     let storage = Storage::default();

    //     // 初始化网络
    //     let (context, receiver) = init_network(&args, storage).unwrap();

    //     // 验证上下文和接收者是否创建成功
    //     assert!(context.handle.is_bound());
    //     assert!(receiver.is_some());
    // }

    // #[test]
    // fn test_context_run() {
    //     // 创建测试上下文
    //     let ctx = Context::default();

    //     // 创建测试接收者
    //     let mut receiver = GossipReceiver::default();

    //     // 运行上下文
    //     ctx.run(receiver).await.unwrap();
    // }

    // #[test]
    // fn test_context_process_gossip() {
    //     // 创建测试上下文
    //     let ctx = Context::default();

    //     // 创建测试事件
    //     let event = Event::Gossip(GossipEvent::Received(IrohMessage::default()));

    //     // 处理事件
    //     ctx.process_gossip(Ok(Some(event))).await;
    // }

    // #[test]
    // fn test_context_process_discovery() {
    //     // 创建测试上下文
    //     let ctx = Context::default();

    //     // 创建测试发现项
    //     let item = Some(Ok(DiscoveryItem::default()));

    //     // 处理发现项
    //     ctx.process_discovery(item).await;
    // }

    // #[test]
    // fn test_context_process_message() {
    //     // 创建测试上下文
    //     let ctx = Context::default();

    //     // 创建测试消息
    //     let message = IrohMessage::default();

    //     // 处理消息
    //     ctx.process_message(message).await;
    // }

    // #[test]
    // fn test_context_broadcast_message() {
    //     // 创建测试上下文
    //     let ctx = Context::default();

    //     // 创建测试消息
    //     let message = Message::AboutMe {
    //         alias: "Test Alias".to_string(),
    //         services: BTreeMap::new(),
    //         invitor: NodeId::default(),
    //     };

    //     // 广播消息
    //     ctx.broadcast_message(message).await.unwrap();
    // }

    // #[test]
    // fn test_context_broadcast_neighbor_message() {
    //     // 创建测试上下文
    //     let ctx = Context::default();

    //     // 创建测试消息
    //     let message = Message::AboutMe {
    //         alias: "Test Alias".to_string(),
    //         services: BTreeMap::new(),
    //         invitor: NodeId::default(),
    //     };

    //     // 广播邻居消息
    //     ctx.broadcast_neighbor_message(message).await.unwrap();
    // }

    // #[test]
    // fn test_context_send_message_to() {
    //     // 创建测试上下文
    //     let ctx = Context::default();

    //     // 创建测试节点 ID
    //     let id = NodeId::default();

    //     // 创建测试消息
    //     let message = Message::AboutMe {
    //         alias: "Test Alias".to_string(),
    //         services: BTreeMap::new(),
    //         invitor: NodeId::default(),
    //     };

    //     // 发送消息
    //     ctx.send_message_to(&id, message).await.unwrap();
    // }
}
