use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures::{FutureExt, StreamExt, TryStreamExt, channel::mpsc::Receiver};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, PublicKey, RelayMode, SecretKey,
    discovery::{
        UserData, mdns::MdnsDiscovery, pkarr::dht::DhtDiscovery, static_provider::StaticProvider,
    },
    protocol::{Router, RouterBuilder},
};
use iroh_gossip::{
    ALPN, Gossip, TopicId,
    api::{Event, GossipReceiver, GossipSender},
};
use rand::{Rng, distr::Alphanumeric};
use tokio::time::{interval, timeout};

use crate::{
    protocol::P2Protocol,
    state,
    storage::Storage,
    types::{Auth, Message, Node, SignedMessage},
    utils::{CliArgs, Ticket, output, time_now},
};

pub const P2P_ALPN: &[u8] = b"/iroh-p2p/0";

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Context {
    pub handle: Endpoint,
    pub storage: Storage,
    pub router: Router,
    pub gossip: Gossip,
    pub(crate) static_provider: StaticProvider,
    pub single_point: P2Protocol,
    pub ticket: Ticket,
    pub nodes: DashMap<EndpointId, Node>,
    pub me: Arc<Node>,
    pub sender: GossipSender,
    pub args: CliArgs,
    pub pending_auth: DashMap<EndpointId, Auth>,
}

pub async fn init_network(
    args: CliArgs,
    storage: Storage,
) -> Result<(Context, GossipReceiver, Receiver<Bytes>, Option<Vec<u8>>)> {
    // When creating a new network, un-trust all nodes and clear cache.
    if args.primary {
        storage.clear()?;
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
        .discovery(sp.clone());

    if let Some(bind) = &args.bind {
        let bind: SocketAddr = bind.parse()?;
        match bind {
            SocketAddr::V4(v4) => {
                endpoint_builder = endpoint_builder.bind_addr_v4(v4);
                if v4.ip().is_loopback() {
                    endpoint_builder = endpoint_builder.bind_addr_v6(SocketAddrV6::new(
                        Ipv6Addr::LOCALHOST,
                        v4.port(),
                        0,
                        0,
                    ));
                }
            }
            SocketAddr::V6(v6) => {
                endpoint_builder = endpoint_builder.bind_addr_v6(v6);
                if v6.ip().is_loopback() {
                    endpoint_builder = endpoint_builder
                        .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, v6.port()));
                }
            }
        }
    } else if let Ok(Some(port)) = storage.load_config::<u16>("bind_port") {
        endpoint_builder = endpoint_builder
            .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
            .bind_addr_v6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
    } else {
        let port = rand::random::<u16>();
        storage.save_config_trival::<u16>("bind_port", port)?;
        endpoint_builder = endpoint_builder
            .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
            .bind_addr_v6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
    }

    if args.daemon && !args.no_mdns {
        endpoint_builder = endpoint_builder.discovery(MdnsDiscovery::builder());
    }

    if args.dht {
        endpoint_builder =
            endpoint_builder.discovery(DhtDiscovery::builder().include_direct_addresses(true));
    }

    let endpoint = endpoint_builder.bind().await?;
    let endpoint_addr = wait_for_non_empty_addr(&endpoint).await;

    let (msg_sender, msg_receiver) = futures::channel::mpsc::channel(1024);
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let p2p = P2Protocol::new(msg_sender);
    let router = RouterBuilder::new(endpoint.clone())
        .accept(ALPN, gossip.clone())
        .accept(P2P_ALPN, p2p.clone())
        .spawn();
    let mut me = Node {
        node_id: pk,
        invitor: invitor.unwrap_or(pk),
        addr: EndpointAddr::new(pk),
        domain,
        services: Default::default(), // reserved
        last_heartbeat: time_now(),
    };
    // Prefer the endpoint's current view of our reachable addresses.
    me.addr = endpoint_addr;
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
        static_provider: sp,
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

async fn wait_for_non_empty_addr(endpoint: &Endpoint) -> EndpointAddr {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let addr = endpoint.addr();
        if addr.ip_addrs().next().is_some() {
            return addr;
        }
        if tokio::time::Instant::now() >= deadline {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

impl Context {
    fn decode_and_verify(&self, bytes: Bytes) -> Result<(PublicKey, Message, bool)> {
        let signed = SignedMessage::decode(bytes)?;
        let (from, message) = signed.verify_and_decode_message()?;
        let passed = self.is_node_trusted(&from) && signed.is_fresh(time_now());
        Ok((from, message, passed))
    }

    fn merge_existing_addr(&self, node_id: &EndpointId, incoming: EndpointAddr) -> EndpointAddr {
        self.nodes
            .get(node_id)
            .map(|node| state::merge_addr(&node.addr, &incoming))
            .unwrap_or(incoming)
    }

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
                    addr: self.handle.addr(),
                    alias: self.me.domain.clone(),
                    services: self.me.services.clone(),
                };
                if self.broadcast_message(invited).await.is_err() {
                    log::error!("Failed to broadcast Invited message to bootstrap the network");
                }
            }
            let about_me = Message::AboutMe {
                addr: self.handle.addr(),
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
                        if let Ok((from, msg, passed)) = self.decode_and_verify(bmsg) {
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

    #[allow(dead_code)]
    pub async fn run_for(
        &self,
        mut gos_recv: GossipReceiver,
        mut sp_recv: Receiver<Bytes>,
        rnum: Option<Vec<u8>>,
        duration: Duration,
    ) {
        let deadline = tokio::time::Instant::now() + duration;
        let mut cron_jobs = interval(Duration::from_millis(200));

        if self.args.daemon {
            if let Some(rnum) = rnum {
                let invited = Message::Invited {
                    topic: self.ticket.topic(),
                    rnum,
                    addr: self.handle.addr(),
                    alias: self.me.domain.clone(),
                    services: self.me.services.clone(),
                };
                let _ = self.broadcast_message(invited).await;
            }

            let about_me = Message::AboutMe {
                addr: self.handle.addr(),
                alias: self.me.domain.clone(),
                services: self.me.services.clone(),
                invitor: self.me.invitor,
            };
            let _ = self.broadcast_message(about_me).await;
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                _ = cron_jobs.tick() => {
                    if self.args.daemon {
                        let mut me = (*self.me).clone();
                        me.addr = self.handle.addr();
                        me.last_heartbeat = time_now();

                        let nodes = self
                            .nodes
                            .iter()
                            .map(|it| it.value().clone())
                            .chain([me])
                            .collect::<Vec<_>>();
                        let _ = self.broadcast_neighbor_message(Message::SyncRequest { nodes }).await;
                    }
                }
                bmsg = sp_recv.next() => {
                    if let Some(bmsg) = bmsg {
                        if let Ok((from, msg, passed)) = self.decode_and_verify(bmsg) {
                            self.process_message(from, msg, passed).await;
                        }
                    } else {
                        break;
                    }
                }
                evt = gos_recv.next() => {
                    match evt {
                        Some(Ok(evt)) => self.process_gossip(Ok(Some(evt))).await,
                        Some(Err(e)) => self.process_gossip(Err(anyhow::anyhow!(e))).await,
                        None => break,
                    }
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

        let nodes_snapshot = self
            .nodes
            .iter()
            .map(|pair| pair.value().clone())
            .collect::<Vec<_>>();
        let nodes_to_remove = state::ids_to_remove_for_duplicate_domains(&nodes_snapshot);

        for node_id in nodes_to_remove {
            self.nodes.remove(&node_id);
        }

        let _ = timeout(Duration::from_secs(1), self.handle.network_change()).await;
    }

    pub async fn update_nodes(&self) {
        let mut me = (*self.me).clone();
        me.addr = self.handle.addr();
        me.last_heartbeat = time_now();

        let nodes = self
            .nodes
            .iter()
            .map(|it| it.value().clone())
            .chain([me])
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
                    if let Ok((from, message, passed)) = self.decode_and_verify(msg.content) {
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
                addr,
                alias,
                services,
            } => {
                if !self.ticket.validate(topic, rnum) {
                    log::error!("Received untrusted Invited message from {:?}", from);
                    return;
                } else {
                    log::info!("Trusting node: {:?} for it holds our ticket", from);
                }

                let addr = if addr.id == from {
                    addr
                } else {
                    EndpointAddr::new(from)
                };
                let addr = self.merge_existing_addr(&from, addr);

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
                if let Some(node) = self.nodes.get(&from) {
                    self.static_provider.add_endpoint_info(node.addr.clone());
                }
                self.ticket.refresh(self);
                log::info!("Node {} joined the chat", from);
                log::info!("New Ticket: {}", self.ticket);
            }
            Message::AboutMe {
                addr,
                alias,
                services,
                invitor,
            } => {
                let addr = if addr.id == from {
                    addr
                } else {
                    EndpointAddr::new(from)
                };
                let addr = self.merge_existing_addr(&from, addr);

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
                        if let Some(node) = self.nodes.get(&from) {
                            self.static_provider.add_endpoint_info(node.addr.clone());
                        }
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
                            let mut node = *auth.node.unwrap();
                            node.addr = self.merge_existing_addr(&id, node.addr.clone());
                            self.nodes.insert(id, node);
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
                    for node in nodes {
                        let existing = self.nodes.get(&node.node_id);
                        let should_update = match existing.as_ref() {
                            None => true,
                            Some(existing) => existing.last_heartbeat < node.last_heartbeat,
                        };
                        if should_update {
                            let (merged, _) = state::merge_node(existing.as_deref(), &node);
                            self.static_provider.add_endpoint_info(merged.addr.clone());
                            self.nodes.insert(merged.node_id, merged);
                        }
                    }
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
                    for node in nodes {
                        let existing = self.nodes.get(&node.node_id);
                        let should_update = match existing.as_ref() {
                            None => true,
                            Some(existing) => existing.last_heartbeat < node.last_heartbeat,
                        };
                        if should_update {
                            let (merged, _) = state::merge_node(existing.as_deref(), &node);
                            self.static_provider.add_endpoint_info(merged.addr.clone());
                            self.nodes.insert(merged.node_id, merged);
                        }
                    }
                }
            }

            #[allow(unreachable_patterns)]
            _ => log::warn!("Unknown message received"),
        }

        let _ = timeout(Duration::from_secs(1), self.handle.network_change()).await;
    }

    pub async fn broadcast_message(&self, message: Message) -> Result<()> {
        log::debug!("Broadcasting message: {:?}", message);
        let bm = SignedMessage::sign_and_encode(self.handle.secret_key(), message)?;
        timeout(Duration::from_secs(3), self.sender.broadcast(bm))
            .await
            .map_err(|_| anyhow::anyhow!("Timed out broadcasting message"))??;
        Ok(())
    }

    pub async fn broadcast_neighbor_message(&self, message: Message) -> Result<()> {
        log::debug!("Broadcasting neighbor message: {:?}", message);
        let bm = SignedMessage::sign_and_encode(self.handle.secret_key(), message)?;
        timeout(Duration::from_secs(3), self.sender.broadcast_neighbors(bm))
            .await
            .map_err(|_| anyhow::anyhow!("Timed out broadcasting neighbor message"))??;
        Ok(())
    }

    pub async fn send_message_to(&self, id: &EndpointId, message: Message) -> Result<()> {
        if id == &self.me.node_id {
            return Ok(());
        }

        log::debug!("Sending message to {:?}: {:?}", id, message);
        let target = self
            .nodes
            .get(id)
            .map(|node| node.addr.clone())
            .unwrap_or_else(|| (*id).into());
        timeout(
            Duration::from_secs(3),
            self.single_point
                .send_msg(self.handle.clone(), target, message),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Timed out sending message to {id:?}"))?
        .inspect_err(|e| log::error!("Failed to send message to {:?}: {:?}", id, e))?;
        Ok(())
    }

    pub fn is_node_trusted(&self, id: &EndpointId) -> bool {
        self.nodes.contains_key(id)
    }
}

// (tests moved into dedicated unit/integration test modules)
