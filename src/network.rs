use std::{
    collections::BTreeMap,
    hash::Hash,
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures::{FutureExt, StreamExt, TryStreamExt, channel::mpsc::Receiver};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, PublicKey, RelayMode, SecretKey, Signature,
    discovery::{UserData, mdns::MdnsDiscovery, static_provider::StaticProvider},
    protocol::{Router, RouterBuilder},
};
use iroh_gossip::{
    ALPN, Gossip, TopicId,
    api::{Event, GossipReceiver, GossipSender},
};
use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use tokio::time::{interval, timeout};

use crate::{
    protocol::P2Protocol,
    storage::Storage,
    utils::{CliArgs, Ticket, output, time_now},
};

pub const P2P_ALPN: &[u8] = b"/iroh-p2p/0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Invited {
        topic: TopicId,
        rnum: Vec<u8>,
        alias: String,
        services: BTreeMap<String, u32>,
    },
    AboutMe {
        alias: String,
        services: BTreeMap<String, u32>,
        invitor: EndpointId,
    },
    Introduce {
        invited: EndpointId,
    },
    SyncRequest {
        nodes: Vec<Node>,
    },
    SyncResponse {
        nodes: Vec<Node>,
    },
    Heartbeat,
    Left,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SignedMessage {
    pub(crate) from: EndpointId,
    pub(crate) data: Bytes,
    signature: Signature,
    timestamp: u64,
}

impl SignedMessage {
    pub fn decode_and_verify(ctx: Context, bytes: Bytes) -> Result<(PublicKey, Message, bool)> {
        let signed_message: Self = postcard::from_bytes(bytes.as_ref())?;
        let key: PublicKey = signed_message.from;

        key.verify(&signed_message.data, &signed_message.signature)?;
        let message: Message = postcard::from_bytes(&signed_message.data)?;
        let passed = ctx.is_node_trusted(&key) && signed_message.timestamp < time_now() + 10;
        Ok((signed_message.from, message, passed))
    }

    pub fn sign_and_encode(secret_key: &SecretKey, message: Message) -> Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        let signature = secret_key.sign(&data);
        let from: PublicKey = secret_key.public();
        let timestamp = time_now();
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
    pub node_id: EndpointId,
    pub invitor: EndpointId,
    pub(crate) addr: EndpointAddr,
    pub domain: String,
    pub services: BTreeMap<String, u32>,
    pub last_heartbeat: u64,
}

#[derive(Debug, Clone)]
pub struct Auth {
    pub introducer: EndpointId,
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
    pub single_point: P2Protocol,
    pub ticket: Ticket,
    pub nodes: DashMap<EndpointId, Node>,
    pub me: Arc<Node>,
    pub sender: GossipSender,
    pub args: CliArgs,
    pub pending_auth: DashMap<EndpointId, Auth>,
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

pub async fn init_network(
    args: CliArgs,
    storage: Storage,
) -> Result<(Context, GossipReceiver, Receiver<Bytes>, Option<Vec<u8>>)> {
    // When creating a new network, un-trust all nodes and clear cache.
    if args.primary {
        storage.clear()?;
    }

    let bind_addr;
    if let Some(bind) = &args.bind {
        bind_addr = bind.parse::<SocketAddrV4>()?;
    } else if let Ok(Some(port)) = storage.load_config::<u16>("bind_port") {
        bind_addr = SocketAddrV4::new(Ipv4Addr::from_str("0.0.0.0").unwrap(), port);
    } else {
        let port = rand::random::<u16>();
        storage.save_config_trival::<u16>("bind_port", port)?;
        bind_addr = SocketAddrV4::new(Ipv4Addr::from_str("0.0.0.0").unwrap(), 0);
    }

    let domain = args.domain.clone().unwrap_or_else(|| {
        let rng = rand::rng();
        rng.sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect()
    });

    // Try to load the secret key from storage, if not found, generate a new one.
    // The public key is used as the node ID to be acknowledged by other nodes.
    let (pk, sk) = storage.load_secret()?.unwrap_or_else(
        #[inline]
        || {
            let mut rng = rand::rng();
            let sk = SecretKey::generate(&mut rng);
            let pk = sk.public();
            storage.save_secret(sk.clone()).unwrap();
            (pk, sk)
        },
    );

    // Set up bootstrap nodes with ticket and storage
    let arg_ticket = Ticket::from_str(args.ticket.as_deref().unwrap_or(""));
    let arg_ticket = arg_ticket.map(|t| t.flatten());
    let has_ticket = arg_ticket.is_ok();
    let (invitor, invitor_node, invitor_rnum, topic) = arg_ticket
        .map(|(topic, rnum, node)| (Some(node.node_id), Some(node), Some(rnum), Some(topic)))
        .unwrap_or((None, None, None, None));

    // Set up discovery:
    // - Local discovery (mDNS) is enabled only in daemon mode
    // - Static discovery is always enabled (for tickets / persisted nodes)
    let sp = StaticProvider::new();
    let mut endpoint_builder = Endpoint::builder()
        .relay_mode(RelayMode::Disabled)
        .secret_key(sk)
        .bind_addr_v4(bind_addr)
        .discovery(sp.clone());

    if args.daemon {
        endpoint_builder = endpoint_builder.discovery(MdnsDiscovery::builder());
    }

    let endpoint = endpoint_builder.bind().await?;

    let (msg_sender, msg_receiver) = futures::channel::mpsc::channel(1024);
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let p2p = P2Protocol::new(msg_sender);
    let router = RouterBuilder::new(endpoint.clone())
        .accept(ALPN, gossip.clone())
        .accept(P2P_ALPN, p2p.clone())
        .spawn();
    let me = Node {
        node_id: pk,
        invitor: invitor.unwrap_or(pk),
        addr: endpoint.addr(),
        domain,
        services: Default::default(), // reserved
        last_heartbeat: time_now(),
    };
    log::debug!("My node: {:?}", me);

    // Generate a ticket for ourself.
    let ticket = if has_ticket {
        storage.save_config_trival::<TopicId>("topic", topic.unwrap())?;
        Ticket::new(topic, me.clone())
    } else if args.primary {
        Ticket::new(None, me.clone())
    } else if let Ok(Some(topic)) = storage.load_config::<TopicId>("topic") {
        Ticket::new(Some(topic), me.clone())
    } else {
        log::error!(
            "We need a ticket to join the network, or set [--primary] to create a new network"
        );
        return Err(anyhow::anyhow!(
            "Network config not found in both storage and ticket"
        ));
    };

    // Loaded nodes from storage may be outdated
    // They should be updated with discoveries.
    // Priority:
    // mdns discovery -> Ticket -> static discovery(inherited from storage)
    let bootstrap_nodes = storage
        .load_nodes::<Vec<_>>()?
        .into_iter()
        .map(|node| (node.node_id, node))
        .collect::<DashMap<EndpointId, Node>>();

    // Setting up static discovery with storage
    bootstrap_nodes.iter().for_each(|node| {
        sp.add_endpoint_info(node.addr.clone());
    });

    // Setting up static discovery with ticket
    if let Some(node) = invitor_node {
        sp.set_endpoint_info(node.addr.clone());
        bootstrap_nodes.insert(node.node_id, node);
    }

    fn load_bootstrap(bootstrap_nodes: &DashMap<EndpointId, Node>) -> Vec<EndpointId> {
        bootstrap_nodes.iter().map(|node| node.node_id).collect()
    }

    if !args.primary && load_bootstrap(&bootstrap_nodes).is_empty() {
        log::warn!("No bootstrap nodes found, add one with ticket or waiting for mdns discovery");
    }

    let (sender, receiver) = if args.primary {
        gossip
            .subscribe(ticket.topic(), load_bootstrap(&bootstrap_nodes))
            .await?
            .split()
    } else {
        let mut retry = 1u8;
        loop {
            if retry > 5 {
                return Err(anyhow::anyhow!("Failed to join gossip"));
            }

            match timeout(
                Duration::from_secs(3),
                gossip.subscribe_and_join(ticket.topic(), load_bootstrap(&bootstrap_nodes)),
            )
            .await
            {
                Ok(Ok(res)) => break res.split(),
                _ => {
                    log::warn!("Timeout joining gossip, retrying {} times...", retry);
                    retry += 1;
                }
            }
        }
    };

    // for now, this takes no effect since we don't handle discovery events manually.
    endpoint.set_user_data_for_discovery(
        args.domain
            .clone()
            .map(|alias| UserData::from_str(alias.as_str()).unwrap()),
    );

    let context = Context {
        handle: endpoint,
        storage,
        router,
        gossip,
        single_point: p2p,
        ticket,
        nodes: bootstrap_nodes,
        me: Arc::new(me),
        sender,
        args,
        pending_auth: DashMap::new(),
    };

    Ok((context, receiver, msg_receiver, invitor_rnum))
}

impl Context {
    pub async fn run(
        &self,
        mut gos_recv: GossipReceiver,
        mut sp_recv: Receiver<Bytes>,
        rnum: Option<Vec<u8>>,
    ) {
        let mut cron_jobs = interval(std::time::Duration::from_secs(30));

        // before join the loop, we still need to broadcast some message to bootstrap ourself.
        if self.args.daemon {
            if let Some(rnum) = rnum {
                let invited = Message::Invited {
                    topic: self.ticket.topic(),
                    rnum,
                    alias: self.me.domain.clone(),
                    services: self.me.services.clone(),
                };
                if self.broadcast_message(invited).await.is_err() {
                    log::error!("Failed to broadcast Invited message to bootstrap the network");
                }
            }
            let about_me = Message::AboutMe {
                alias: self.me.domain.clone(),
                services: self.me.services.clone(),
                invitor: self.me.invitor,
            };
            if self.broadcast_message(about_me).await.is_err() && !self.args.primary {
                log::error!("Failed to broadcast AboutMe message to bootstrap the network");
            }
        }

        // Errors are expected if we are the first node in network.
        // TODO: a smarter sync strategy
        let sync_req = Message::SyncRequest {
            nodes: Default::default(),
        };
        let _ = self.broadcast_neighbor_message(sync_req).await;

        loop {
            let ctrlc = tokio::signal::ctrl_c().fuse();
            let ctrlc = std::pin::pin!(ctrlc);

            futures::select! {
                _ = ctrlc.fuse() => {
                    log::info!("Shutting down...");
                    self.graceful_shutdown().await;
                    break;
                },
                _ = cron_jobs.tick().fuse() => {
                    if self.args.daemon {
                        let _ = self.broadcast_message(Message::Heartbeat).await;
                        self.update_nodes().await;
                    }
                    output(self.clone());

                    self.cleanup().await;
                    if let Err(e) = self.save().await {
                        log::error!("Failed to save nodes to storage: {:?}", e);
                    }
                },
                bmsg = sp_recv.next().fuse() => {
                    if let Some(bmsg) = bmsg {
                        if let Ok((from, msg, passed)) = SignedMessage::decode_and_verify(self.clone(), bmsg) {
                            log::debug!("Received p2p msg: {:?}", msg);
                            self.process_message(from, msg, passed).await;
                        } else {
                            log::error!("Failed to decode and verify message from p2p");
                        }
                    }
                },
                evt = gos_recv.try_next().fuse() => {
                    self.process_gossip(evt.map_err(|e| anyhow::anyhow!(e))).await;
                }
            }
        }
    }

    pub async fn graceful_shutdown(&self) {
        if self.args.daemon {
            let _ = self.broadcast_message(Message::Left).await;
        }

        let _ = self.save().await;
        let _ = self.router.shutdown().await;
        self.handle.close().await;
    }

    pub async fn save(&self) -> Result<()> {
        self.nodes.remove(&self.me.node_id);

        log::debug!("Saving {} nodes to storage", self.nodes.len());
        let nodes = self
            .nodes
            .iter()
            .map(|it| it.value().clone())
            .collect::<Vec<_>>();
        self.storage.batch_save_nodes(nodes.into_iter())?;

        Ok(())
    }

    pub async fn cleanup(&self) {
        let now = time_now();
        self.pending_auth
            .retain(|_, auth| now - auth.timestamp < 60 * 5);

        // Clean up nodes that have the same alias name.
        // Find nodes with duplicate aliases, keeping only the most recent one
        let mut by_alias: std::collections::HashMap<String, (EndpointId, u64)> =
            std::collections::HashMap::new();
        for pair in self.nodes.iter() {
            let node = pair.value();
            by_alias
                .entry(node.domain.clone())
                .and_modify(|(id, heartbeat)| {
                    if node.last_heartbeat > *heartbeat {
                        *id = node.node_id;
                        *heartbeat = node.last_heartbeat;
                    }
                })
                .or_insert((node.node_id, node.last_heartbeat));
        }

        let nodes_to_remove = {
            let mut to_remove = Vec::new();
            for pair in self.nodes.iter() {
                let node = pair.value();
                if let Some((best_id, _)) = by_alias.get(&node.domain)
                    && *best_id != node.node_id
                {
                    to_remove.push(node.node_id);
                }
            }
            to_remove
        };

        // Remove nodes that have the same alias but aren't the most recent
        for node_id in nodes_to_remove {
            self.nodes.remove(&node_id);
        }

        self.handle.network_change().await;
    }

    pub async fn update_nodes(&self) {
        let nodes = self
            .nodes
            .iter()
            .map(|it| it.value().clone())
            .chain([self.me.as_ref().clone()])
            .collect::<Vec<_>>();
        let _ = self
            .broadcast_neighbor_message(Message::SyncRequest { nodes })
            .await;
    }

    async fn process_gossip(&self, evt: Result<Option<Event>>) {
        match evt {
            Ok(Some(evt)) => match evt {
                Event::NeighborDown(endpoint_id) => {
                    self.pending_auth.remove(&endpoint_id);
                }
                Event::Received(msg) => {
                    if let Ok((from, message, passed)) =
                        SignedMessage::decode_and_verify(self.clone(), msg.content)
                    {
                        self.process_message(from, message, passed).await;
                    }
                }
                Event::Lagged => log::warn!("Gossip receiver lagged; consider restarting it"),
                Event::NeighborUp(_) => {}
            },
            Err(e) => log::error!("Error processing gossip event: {:?}", e),
            _ => {}
        }
    }

    async fn process_message(&self, from: EndpointId, message: Message, passed: bool) {
        log::debug!("Received message from {:?}", from);
        log::debug!("Message: {:?}", message);

        if passed {
            self.nodes.alter(&from, |_, mut node| {
                node.last_heartbeat = time_now();
                node
            });
        }

        match message {
            Message::Invited {
                topic,
                rnum,
                alias,
                services,
            } => {
                if !self.ticket.validate(topic, rnum) {
                    log::error!("Received untrusted Invited message from {:?}", from);
                    return;
                } else {
                    log::info!("Trusting node: {:?} for it holds our ticket", from);
                }

                let addr = EndpointAddr::new(from);

                let node = Node {
                    node_id: from,
                    invitor: self.me.node_id,
                    addr,
                    domain: alias,
                    services,
                    last_heartbeat: 0,
                };

                self.pending_auth.remove(&from);
                self.nodes.insert(from, node);
                self.ticket.refresh(self.clone());
                log::info!("Node {} joined the chat", from);
                log::info!("New Ticket: {}", self.ticket);
            }
            Message::AboutMe {
                alias,
                services,
                invitor,
            } => {
                let addr = EndpointAddr::new(from);

                let node = Node {
                    node_id: from,
                    invitor,
                    addr,
                    domain: alias,
                    services,
                    last_heartbeat: 0,
                };

                if self.pending_auth.contains_key(&from) {
                    let auth = self.pending_auth.get(&from).unwrap();
                    if auth.introduced {
                        // We already reveived a message from this node, but it was not introduced.
                        // Simply update the information.
                        self.pending_auth.alter(&from, |_, auth| Auth {
                            introducer: auth.introducer,
                            introduced: false,
                            node: auth.node,
                            timestamp: time_now(),
                        });
                    } else {
                        // This node has been introduced, we can trust it now.
                        self.pending_auth.remove(&from);
                        self.nodes.insert(from, node);
                    }
                } else {
                    // This node has not been introduced yet.
                    let auth = Auth {
                        introducer: from,
                        introduced: false,
                        node: Box::new(node).into(),
                        timestamp: time_now(),
                    };
                    self.pending_auth.insert(from, auth);
                }
            }
            Message::Introduce { invited } => {
                if !passed {
                    log::error!("Received untrusted Introduce message from {:?}", from);
                    return;
                }
                log::info!("Received Introduce message from {:?}", from);
                if self.pending_auth.contains_key(&from) {
                    let auth = self.pending_auth.get(&from).unwrap();
                    if auth.introduced {
                        self.pending_auth.alter(&from, |_, auth| Auth {
                            introducer: auth.introducer,
                            introduced: true,
                            node: auth.node,
                            timestamp: time_now(),
                        });
                    } else {
                        // This node has sent 'AboutMe' message before.
                        assert!(auth.node.is_some());
                        if let Some((id, auth)) = self.pending_auth.remove(&from) {
                            let node = auth.node.unwrap();
                            self.nodes.insert(id, *node);
                        }
                    }
                } else {
                    let auth = Auth {
                        introducer: from,
                        introduced: true,
                        node: None,
                        timestamp: time_now(),
                    };
                    self.pending_auth.insert(invited, auth);
                }
            }
            Message::Heartbeat => {}
            Message::Left => {
                if !passed {
                    log::error!("Received untrusted Left message from {:?}", from);
                    return;
                }
            }
            Message::SyncRequest { nodes } => {
                if !self.args.daemon || passed {
                    nodes.iter().for_each(|node| {
                        let should_update = {
                            let target = self.nodes.get(&node.node_id);
                            target.is_none()
                                || target
                                    .as_ref()
                                    .is_some_and(|t| t.last_heartbeat < node.last_heartbeat)
                        };
                        if should_update {
                            log::debug!("Updating node: {:?}", node);
                            self.nodes.insert(node.node_id, node.clone());
                        }
                    });
                }

                if self.args.daemon {
                    let nodes = self
                        .nodes
                        .iter()
                        .map(|t| t.value().clone())
                        .chain([self.me.as_ref().clone()])
                        .collect::<Vec<_>>();

                    let message = Message::SyncResponse { nodes };
                    if let Err(e) = self.send_message_to(&from, message).await {
                        log::error!("Failed to send SyncResponse to {:?}: {:?}", from, e);
                    }
                }
            }
            Message::SyncResponse { nodes } => {
                // A message from a trusted node is always valid.
                // Or if we are a client, we simply trust everything.
                if !self.args.daemon || passed {
                    nodes.iter().for_each(|node| {
                        let should_update = {
                            let target = self.nodes.get(&node.node_id);
                            target.is_none()
                                || target
                                    .as_ref()
                                    .is_some_and(|t| t.last_heartbeat < node.last_heartbeat)
                        };
                        if should_update {
                            log::debug!("Updating node: {:?}", node);
                            self.nodes.insert(node.node_id, node.clone());
                        }
                    });
                }
            }

            #[allow(unreachable_patterns)]
            _ => log::warn!("Unknown message received"),
        }

        self.handle.network_change().await;
    }

    pub async fn broadcast_message(&self, message: Message) -> Result<()> {
        log::debug!("Broadcasting message: {:?}", message);
        let bm = SignedMessage::sign_and_encode(self.handle.secret_key(), message)?;
        self.sender.broadcast(bm).await?;
        Ok(())
    }

    pub async fn broadcast_neighbor_message(&self, message: Message) -> Result<()> {
        log::debug!("Broadcasting neighbor message: {:?}", message);
        let bm = SignedMessage::sign_and_encode(self.handle.secret_key(), message)?;
        self.sender.broadcast_neighbors(bm).await?;
        Ok(())
    }

    pub async fn send_message_to(&self, id: &EndpointId, message: Message) -> Result<()> {
        if id == &self.me.node_id {
            return Ok(());
        }

        log::debug!("Sending message to {:?}: {:?}", id, message);
        self.single_point
            .send_msg(self.handle.clone(), *id, message)
            .await
            .inspect_err(|e| log::error!("Failed to send message to {:?}: {:?}", id, e))?;
        Ok(())
    }

    pub fn is_node_trusted(&self, id: &EndpointId) -> bool {
        self.nodes.contains_key(id)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    impl Node {
        pub fn random_node() -> Self {
            let mut rng = rand::rng();
            let sk = SecretKey::generate(&mut rng);
            let pk = sk.public();

            Self {
                node_id: pk,
                invitor: pk,
                domain: String::default(),
                services: BTreeMap::new(),
                last_heartbeat: 0,
                addr: EndpointAddr::new(pk),
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
