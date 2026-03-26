pub mod p2p_protocol;

use std::{
    io::IsTerminal,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures::{FutureExt, StreamExt, TryStreamExt, channel::mpsc::Receiver};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, PublicKey, RelayMap, RelayMode, RelayUrl, SecretKey,
    discovery::{UserData, mdns::MdnsDiscovery, static_provider::StaticProvider},
    protocol::{Router, RouterBuilder},
};
use iroh_gossip::{
    ALPN, Gossip, TopicId,
    api::{Event, GossipReceiver, GossipSender},
    proto::HyparviewConfig,
};
use parking_lot::RwLock;
use rand::{Rng, distr::Alphanumeric};
use tokio::time::{interval, timeout};

use crate::{
    cli::args::{DaemonArgs, RelayModeArg},
    domain::{
        client::{HostsSyncStatus, SERVICE_MARKER_CLIENT},
        merge,
        message::{Message, SignedMessage},
        node::Node,
        ticket::Ticket,
    },
    hosts,
    net::p2p_protocol::P2Protocol,
    storage::Storage,
    util::{
        BindTarget, best_endpoint_addr_for_local, lookup_interface_addrs, parse_bind_target,
        time_now,
    },
};

const STALE_NODE_TTL_SECS: u64 = 90;
const STATE_BROADCAST_INTERVAL_SECS: u64 = 30;
const FULL_SYNC_INTERVAL_SECS: u64 = 5 * 60;

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
    pub args: DaemonArgs,
    started_at: u64,
    join_announced: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    hosts_sync: Arc<RwLock<HostsSyncStatus>>,
}

pub async fn init_network(
    args: DaemonArgs,
    storage: Storage,
) -> Result<(Context, GossipReceiver, Receiver<Bytes>)> {
    // Explicit reset (dangerous): clears secret/topic/nodes. This is required if the user wants to
    // intentionally create a brand-new network on an existing config directory.
    if args.reset_storage {
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
            if let Err(e) = storage.save_secret(sk.clone()) {
                log::error!("Failed to persist secret key: {}", e);
            }
            (pk, sk)
        },
    );

    // Set up bootstrap nodes with ticket and storage
    let arg_ticket = match args.ticket.as_deref() {
        Some(ticket) => Some(Ticket::from_str(ticket)?),
        None => None,
    };
    let (invitor, invitor_node) = match arg_ticket.as_ref() {
        Some(ticket) => {
            let (_, _, node) = ticket.flatten();
            (Some(node.node_id), Some(node))
        }
        None => (None, None),
    };

    // Set up discovery:
    // - Local discovery (mDNS) is enabled only in daemon mode
    // - Static discovery is always enabled (for tickets / persisted nodes)
    let sp = StaticProvider::new();
    let relay_mode = if !args.relay_url.is_empty() {
        let relay_urls: Vec<RelayUrl> = args
            .relay_url
            .iter()
            .map(|s| s.parse::<RelayUrl>())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let relay_map: RelayMap = relay_urls.into_iter().collect();
        RelayMode::Custom(relay_map)
    } else {
        match args.relay_mode {
            RelayModeArg::Disabled => RelayMode::Disabled,
            RelayModeArg::Default => RelayMode::Default,
            RelayModeArg::Staging => RelayMode::Staging,
        }
    };
    // IMPORTANT: `Endpoint::builder()` uses the `presets::N0` preset, which enables the
    // n0.computer DNS/PKARR publisher by default (external network). This project wants to be
    // able to run fully offline, so start from an empty builder.
    let mut bind_v4: Option<SocketAddrV4> = None;
    let mut bind_v6: Option<SocketAddrV6> = None;
    let mut prefer_v6_fallback = false;

    let load_or_assign_bind_port = || -> Result<u16> {
        if let Some(port) = storage.load_config::<u16>("bind_port")? {
            Ok(port)
        } else {
            let port = rand::random::<u16>();
            storage.save_config_trival::<u16>("bind_port", port)?;
            Ok(port)
        }
    };

    if let Some(bind) = &args.bind {
        let bind = parse_bind_target(bind)?;
        match bind {
            BindTarget::Socket(SocketAddr::V4(v4)) => {
                bind_v4 = Some(v4);
                if v4.ip().is_loopback() {
                    bind_v6 = Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, v4.port(), 0, 0));
                } else if v4.ip().is_unspecified() {
                    // Treat `0.0.0.0:PORT` as "listen on all addresses", including IPv6 when
                    // available. This helps IPv6-only environments where users may still pass the
                    // IPv4 wildcard out of habit.
                    bind_v6 = Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, v4.port(), 0, 0));
                }
            }
            BindTarget::Socket(SocketAddr::V6(v6)) => {
                bind_v6 = Some(v6);
                prefer_v6_fallback = true;
                if v6.ip().is_loopback() {
                    bind_v4 = Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, v6.port()));
                } else if v6.ip().is_unspecified() {
                    // Treat `[::]:PORT` as "listen on all addresses", including IPv4 when
                    // available.
                    bind_v4 = Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, v6.port()));
                }
            }
            BindTarget::Ip(std::net::IpAddr::V4(ip)) => {
                let port = load_or_assign_bind_port()?;
                bind_v4 = Some(SocketAddrV4::new(ip, port));
                if ip.is_loopback() {
                    bind_v6 = Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
                } else if ip.is_unspecified() {
                    bind_v6 = Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
                }
            }
            BindTarget::Ip(std::net::IpAddr::V6(ip)) => {
                let port = load_or_assign_bind_port()?;
                bind_v6 = Some(SocketAddrV6::new(ip, port, 0, 0));
                prefer_v6_fallback = true;
                if ip.is_loopback() {
                    bind_v4 = Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
                } else if ip.is_unspecified() {
                    bind_v4 = Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
                }
            }
        }
    } else if let Some(interface) = args.bind_interface.as_deref() {
        let port = load_or_assign_bind_port()?;
        let addrs = lookup_interface_addrs(interface)?;
        if let Some(ip) = addrs.v4.first().copied() {
            bind_v4 = Some(SocketAddrV4::new(ip, port));
        }
        if let Some((ip, scope_id)) = addrs.v6.first().copied() {
            bind_v6 = Some(SocketAddrV6::new(ip, port, 0, scope_id));
        }
        prefer_v6_fallback = bind_v4.is_none() && bind_v6.is_some();
    } else {
        let port = load_or_assign_bind_port()?;
        bind_v4 = Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        bind_v6 = Some(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        prefer_v6_fallback = true;
    }

    async fn bind_endpoint(
        args: &DaemonArgs,
        sk: &SecretKey,
        sp: &StaticProvider,
        relay_mode: &RelayMode,
        bind_v4: Option<SocketAddrV4>,
        bind_v6: Option<SocketAddrV6>,
    ) -> Result<Endpoint> {
        let mut builder = Endpoint::empty_builder(relay_mode.clone())
            .secret_key(sk.clone())
            .discovery(sp.clone());

        if args.daemon && !args.no_mdns {
            builder = builder.discovery(MdnsDiscovery::builder());
        }

        if args.dht {
            #[cfg(feature = "pkarr-dht")]
            {
                use iroh::discovery::pkarr::dht::DhtDiscovery;
                builder = builder.discovery(DhtDiscovery::builder().include_direct_addresses(true));
            }
            #[cfg(not(feature = "pkarr-dht"))]
            {
                anyhow::bail!(
                    "`--dht` was requested, but this build was compiled without PKARR/DHT support. Rebuild with `--features pkarr-dht`."
                );
            }
        }

        if let Some(addr) = bind_v4 {
            builder = builder.bind_addr_v4(addr);
        }
        if let Some(addr) = bind_v6 {
            builder = builder.bind_addr_v6(addr);
        }

        Ok(builder.bind().await?)
    }

    let endpoint = match bind_endpoint(&args, &sk, &sp, &relay_mode, bind_v4, bind_v6).await {
        Ok(endpoint) => endpoint,
        Err(primary_err) => {
            if bind_v4.is_some() && bind_v6.is_some() {
                let mut attempts = Vec::new();

                let first = if prefer_v6_fallback {
                    (None, bind_v6)
                } else {
                    (bind_v4, None)
                };
                let second = if prefer_v6_fallback {
                    (bind_v4, None)
                } else {
                    (None, bind_v6)
                };

                match bind_endpoint(&args, &sk, &sp, &relay_mode, first.0, first.1).await {
                    Ok(endpoint) => {
                        log::warn!(
                            "Failed to bind dual-stack endpoint; falling back to single-stack. err={primary_err:#}"
                        );
                        endpoint
                    }
                    Err(e) => {
                        attempts.push(e);
                        match bind_endpoint(&args, &sk, &sp, &relay_mode, second.0, second.1).await
                        {
                            Ok(endpoint) => {
                                log::warn!(
                                    "Failed to bind dual-stack endpoint; falling back to single-stack. err={primary_err:#}"
                                );
                                endpoint
                            }
                            Err(e2) => {
                                attempts.push(e2);
                                anyhow::bail!(
                                    "failed to bind endpoint (dual-stack): {primary_err:#}\n\
fallback attempts: {:#?}",
                                    attempts
                                );
                            }
                        }
                    }
                }
            } else {
                return Err(primary_err);
            }
        }
    };
    let endpoint_addr = wait_for_non_empty_addr(&endpoint).await;

    let (msg_sender, msg_receiver) = futures::channel::mpsc::channel(1024);
    let mut membership = HyparviewConfig::default();
    if args.primary {
        // The default HyParView active view size (5) can prevent all daemons from joining in
        // multi-subnet deployments where the primary is the only routable bridge between networks.
        membership.active_view_capacity = 32;
        membership.passive_view_capacity = 128;
    }
    let gossip = Gossip::builder()
        .membership_config(membership)
        .spawn(endpoint.clone());
    let p2p = P2Protocol::new(msg_sender);
    let router = RouterBuilder::new(endpoint.clone())
        .accept(ALPN, gossip.clone())
        .accept(P2Protocol::P2P_ALPN, p2p.clone())
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

    // Generate/load the network ticket.
    //
    // Primary nodes should keep the topic/rnum stable across restarts so that existing daemons can
    // continue to join after a reboot. Use `--reset-storage` to intentionally rotate everything.
    let ticket = if args.primary {
        let topic: Option<TopicId> = storage.load_config("topic")?;
        let rnum: Option<Vec<u8>> = storage.load_config("ticket_rnum")?;
        match (topic, rnum) {
            (Some(topic), Some(rnum)) => Ticket::from_parts(topic, rnum, me.clone()),
            _ => {
                let ticket = Ticket::new(None, me.clone());
                let (topic, rnum, _) = ticket.flatten();
                storage.save_config_trival::<TopicId>("topic", topic)?;
                storage.save_config::<_, Vec<u8>>("ticket_rnum", rnum)?;
                ticket
            }
        }
    } else if let Some(ticket) = arg_ticket {
        let (topic, rnum, _) = ticket.flatten();
        storage.save_config_trival::<TopicId>("topic", topic)?;
        storage.save_config::<_, Vec<u8>>("ticket_rnum", rnum)?;
        ticket
    } else {
        let topic: Option<TopicId> = storage.load_config("topic")?;
        let rnum: Option<Vec<u8>> = storage.load_config("ticket_rnum")?;
        match (topic, rnum) {
            (Some(topic), Some(rnum)) => Ticket::from_parts(topic, rnum, me.clone()),
            _ => {
                log::error!(
                    "We need a ticket to join the network, or set [--primary] to create a new network"
                );
                return Err(anyhow::anyhow!(
                    "Network config not found in both storage and ticket"
                ));
            }
        }
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

    // Setting up static discovery with storage.
    //
    // IMPORTANT: Keep all known addresses here. A ticket is not a rendezvous system; it only
    // contains "contact info". If we collapse it to a single address and pick the wrong one
    // (e.g. private vs public, v4 vs v6, wrong interface), joins can fail even though other
    // addresses in the ticket would have worked.
    bootstrap_nodes
        .iter()
        .filter(|node| !node.addr.is_empty())
        .for_each(|node| {
            sp.add_endpoint_info(node.addr.clone());
        });

    // Setting up static discovery with ticket (keep all addresses).
    if let Some(node) = invitor_node {
        if !node.addr.is_empty() {
            sp.set_endpoint_info(node.addr.clone());
        }
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
                Duration::from_secs(20),
                gossip.subscribe_and_join(ticket.topic(), load_bootstrap(&bootstrap_nodes)),
            )
            .await
            {
                Ok(Ok(res)) => break res.split(),
                _ => {
                    if retry == 1 && relay_mode == RelayMode::Disabled && args.relay_url.is_empty()
                    {
                        log::warn!(
                            "Failed to join gossip; relay is disabled so this only works on LAN (mDNS) or with routable addresses in the ticket."
                        );
                    }
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

    let hosts_sync = Arc::new(RwLock::new(HostsSyncStatus {
        enabled: args.hosts_sync,
        path: hosts_sync_path(&args).map(|p| p.display().to_string()),
        cleanup_on_shutdown: args.hosts_sync,
        last_success: None,
        last_cleanup: None,
        last_error: None,
    }));

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
        started_at: time_now(),
        join_announced: Arc::new(AtomicBool::new(false)),
        paused: Arc::new(AtomicBool::new(false)),
        hosts_sync,
    };

    if context.args.daemon && !context.args.primary {
        context.announce_join().await;
    }

    Ok((context, receiver, msg_receiver))
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
    fn hosts_sync_path(&self) -> Option<PathBuf> {
        hosts_sync_path(&self.args)
    }

    pub fn hosts_sync_status(&self) -> HostsSyncStatus {
        self.hosts_sync.read().clone()
    }

    fn set_hosts_sync_error(&self, err: impl Into<String>) {
        let mut status = self.hosts_sync.write();
        status.last_error = Some(err.into());
    }

    pub fn sync_hosts_file(&self) -> Result<bool> {
        if !self.args.hosts_sync {
            return Ok(false);
        }

        let Some(hosts_path) = self.hosts_sync_path() else {
            anyhow::bail!("hosts sync is enabled but no hosts path is available");
        };

        let nodes = self
            .nodes
            .iter()
            .map(|entry| entry.value().clone())
            .chain([self.me.as_ref().clone()])
            .collect::<Vec<_>>();

        match hosts::sync_nodes_to_hosts(
            &hosts_path,
            &self.handle.addr(),
            nodes,
            self.args.hosts_suffix.as_deref(),
        ) {
            Ok(changed) => {
                let mut status = self.hosts_sync.write();
                status.last_success = Some(time_now());
                status.last_error = None;
                Ok(changed)
            }
            Err(err) => {
                self.set_hosts_sync_error(err.to_string());
                Err(err.into())
            }
        }
    }

    pub fn clear_hosts_file(&self) -> Result<bool> {
        if !self.args.hosts_sync {
            return Ok(false);
        }

        let Some(hosts_path) = self.hosts_sync_path() else {
            anyhow::bail!("hosts cleanup is enabled but no hosts path is available");
        };

        match hosts::clear_managed_hosts(&hosts_path) {
            Ok(changed) => {
                let mut status = self.hosts_sync.write();
                status.last_cleanup = Some(time_now());
                status.last_error = None;
                Ok(changed)
            }
            Err(err) => {
                self.set_hosts_sync_error(err.to_string());
                Err(err.into())
            }
        }
    }

    fn decode_and_verify(&self, bytes: Bytes) -> Result<(PublicKey, Message, bool)> {
        let signed = SignedMessage::decode(bytes)?;
        let (from, message) = signed.verify_and_decode_message()?;
        let passed = self.is_node_trusted(&from) && signed.is_fresh(time_now());
        Ok((from, message, passed))
    }

    fn merge_existing_addr(&self, node_id: &EndpointId, incoming: EndpointAddr) -> EndpointAddr {
        self.nodes
            .get(node_id)
            .map(|node| merge::merge_addr(&node.addr, &incoming))
            .unwrap_or(incoming)
    }

    async fn announce_join(&self) {
        if self.join_announced.load(Ordering::Relaxed) {
            return;
        }

        if !self.args.daemon || self.args.primary {
            return;
        }

        let invited = Message::Invited {
            topic: self.ticket.topic(),
            rnum: self.ticket.rnum(),
            addr: self.handle.addr(),
            alias: self.me.domain.clone(),
            services: self.me.services.clone(),
            invitor: self.me.invitor,
        };

        if let Err(e) = self.broadcast_message(invited).await {
            log::warn!("Failed to announce join (Invited): {e}");
            return;
        }

        self.join_announced.store(true, Ordering::Relaxed);
    }

    pub async fn run(&self, mut gos_recv: GossipReceiver, mut sp_recv: Receiver<Bytes>) {
        let mut state_broadcast = interval(Duration::from_secs(STATE_BROADCAST_INTERVAL_SECS));
        let mut full_sync = interval(Duration::from_secs(FULL_SYNC_INTERVAL_SECS));
        let interactive = std::io::stdin().is_terminal();
        let mut ctrlc = Box::pin(tokio::signal::ctrl_c()).fuse();
        let mut sigterm = Box::pin(async {
            #[cfg(unix)]
            {
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(mut signal) => {
                        let _ = signal.recv().await;
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to listen for SIGTERM signal: {e}; continuing without SIGTERM handling"
                        );
                        futures::future::pending::<()>().await;
                    }
                }
            }
            #[cfg(not(unix))]
            {
                futures::future::pending::<()>().await;
            }
        })
        .fuse();

        // Errors are expected if we are the first node in network.
        // TODO: a smarter sync strategy
        self.request_neighbor_sync().await;

        loop {
            futures::select! {
                res = ctrlc => {
                    match res {
                        Ok(()) => {
                            if self.args.daemon && !interactive {
                                // In daemon/container scenarios stdout/stderr are usually not
                                // attached to a TTY. Treat SIGINT as non-fatal to avoid
                                // accidental shutdown from signal proxying.
                                log::warn!(
                                    "Received SIGINT in non-interactive daemon mode; ignoring (use SIGTERM or admin shutdown)"
                                );
                            } else {
                                log::info!("Shutting down (SIGINT)...");
                                self.graceful_shutdown().await;
                                break;
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to listen for Ctrl-C signal: {e}; continuing without signal handling");
                        }
                    }
                },
                _ = sigterm => {
                    log::info!("Shutting down (SIGTERM)...");
                    self.graceful_shutdown().await;
                    break;
                },
                _ = state_broadcast.tick().fuse() => {
                    if self.args.daemon && !self.is_paused() {
                        self.broadcast_state_update().await;
                    }
                    self.cleanup().await;
                    if let Err(e) = self.save().await {
                        log::error!("Failed to save nodes to storage: {:?}", e);
                    }
                },
                _ = full_sync.tick().fuse() => {
                    if self.args.daemon && !self.is_paused() {
                        self.request_neighbor_sync().await;
                    }
                },
                bmsg = sp_recv.next().fuse() => {
                    match bmsg {
                        Some(bmsg) => {
                            if let Ok((from, msg, passed)) = self.decode_and_verify(bmsg) {
                                log::debug!("Received p2p msg: {:?}", msg);
                                self.process_message(from, msg, passed).await;
                            } else {
                                log::error!("Failed to decode and verify message from p2p");
                            }
                        }
                        None => {
                            log::info!("P2P receiver closed; stopping daemon event loop");
                            break;
                        }
                    }
                },
                evt = gos_recv.try_next().fuse() => {
                    match evt {
                        Ok(Some(evt)) => self.process_gossip(Ok(Some(evt))).await,
                        Ok(None) => {
                            log::info!("Gossip receiver closed; stopping daemon event loop");
                            break;
                        }
                        Err(e) => self.process_gossip(Err(anyhow::anyhow!(e))).await,
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    pub async fn run_for(
        &self,
        mut gos_recv: GossipReceiver,
        mut sp_recv: Receiver<Bytes>,
        duration: Duration,
    ) {
        let deadline = tokio::time::Instant::now() + duration;
        let mut state_broadcast = interval(Duration::from_millis(200));
        let mut full_sync = interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                _ = state_broadcast.tick() => {
                    if self.args.daemon {
                        self.broadcast_state_update().await;
                    }
                }
                _ = full_sync.tick() => {
                    if self.args.daemon {
                        self.request_neighbor_sync().await;
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

        if self.args.hosts_sync
            && let Err(e) = self.clear_hosts_file()
        {
            log::error!("Failed to clean hosts file on shutdown: {e:#}");
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

        let stale_node_ids = self
            .nodes
            .iter()
            .filter_map(|pair| {
                let node = pair.value();
                if node.services.contains_key(SERVICE_MARKER_CLIENT) {
                    return None;
                }

                (now.saturating_sub(node.last_heartbeat) > STALE_NODE_TTL_SECS)
                    .then_some(*pair.key())
            })
            .collect::<Vec<_>>();

        for node_id in stale_node_ids {
            self.nodes.remove(&node_id);
        }

        let nodes_snapshot = self
            .nodes
            .iter()
            .map(|pair| pair.value().clone())
            .collect::<Vec<_>>();
        let nodes_to_remove = merge::ids_to_remove_for_duplicate_domains(&nodes_snapshot);

        for node_id in nodes_to_remove {
            self.nodes.remove(&node_id);
        }

        let _ = timeout(Duration::from_secs(1), self.handle.network_change()).await;
    }

    fn current_node_state(&self) -> Node {
        let mut me = (*self.me).clone();
        me.addr = self.handle.addr();
        me.last_heartbeat = time_now();
        me
    }

    pub async fn broadcast_state_update(&self) {
        let me = self.current_node_state();
        let _ = self
            .broadcast_message(Message::AboutMe {
                addr: me.addr,
                alias: me.domain,
                services: me.services,
                invitor: me.invitor,
            })
            .await;
    }

    pub async fn request_neighbor_sync(&self) {
        let _ = self
            .broadcast_neighbor_message(Message::SyncRequest { nodes: vec![] })
            .await;
    }

    async fn process_gossip(&self, evt: Result<Option<Event>>) {
        match evt {
            Ok(Some(evt)) => match evt {
                Event::NeighborDown(_endpoint_id) => {}
                Event::Received(msg) => {
                    if let Ok((from, message, passed)) = self.decode_and_verify(msg.content) {
                        self.process_message(from, message, passed).await;
                    }
                }
                Event::Lagged => log::warn!("Gossip receiver lagged; consider restarting it"),
                Event::NeighborUp(_) => {
                    self.announce_join().await;
                }
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
                invitor,
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
                    invitor,
                    addr,
                    domain: alias,
                    services,
                    last_heartbeat: time_now(),
                };

                self.nodes.insert(from, node);
                if let Some(node) = self.nodes.get(&from) {
                    self.static_provider.add_endpoint_info(node.addr.clone());
                }
                log::info!("Node {} joined the chat", from);
            }
            Message::AboutMe {
                addr,
                alias,
                services,
                invitor,
            } => {
                if !passed {
                    log::warn!("Ignoring untrusted AboutMe message from {:?}", from);
                    return;
                }

                let addr = if addr.id == from {
                    addr
                } else {
                    EndpointAddr::new(from)
                };
                let addr = self.merge_existing_addr(&from, addr);

                if self.nodes.contains_key(&from) {
                    let node = Node {
                        node_id: from,
                        invitor,
                        addr,
                        domain: alias,
                        services,
                        last_heartbeat: time_now(),
                    };
                    self.nodes.insert(from, node);
                    if let Some(node) = self.nodes.get(&from) {
                        self.static_provider.add_endpoint_info(node.addr.clone());
                    }
                } else {
                    log::warn!("Ignoring AboutMe for unknown node {:?}", from);
                }
            }
            Message::Introduce { invited } => {
                log::debug!(
                    "Ignoring legacy Introduce message from {:?} for {:?}",
                    from,
                    invited
                );
            }
            Message::Heartbeat => {}
            Message::Left => {
                if !passed {
                    log::error!("Received untrusted Left message from {:?}", from);
                    return;
                }
                self.nodes.remove(&from);
                log::info!("Node {} left the network", from);
            }
            Message::SyncRequest { nodes } => {
                if !self.args.daemon || passed {
                    for node in nodes {
                        let existing = self.nodes.get(&node.node_id).map(|it| it.value().clone());
                        let should_update = match existing.as_ref() {
                            None => true,
                            Some(existing) => existing.last_heartbeat < node.last_heartbeat,
                        };
                        if should_update {
                            let (merged, _) = merge::merge_node(existing.as_ref(), &node);
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
                        let existing = self.nodes.get(&node.node_id).map(|it| it.value().clone());
                        let should_update = match existing.as_ref() {
                            None => true,
                            Some(existing) => existing.last_heartbeat < node.last_heartbeat,
                        };
                        if should_update {
                            let (merged, _) = merge::merge_node(existing.as_ref(), &node);
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
        let local = self.handle.addr();
        let target = self
            .nodes
            .get(id)
            .map(|node| best_endpoint_addr_for_local(&node.addr, &local))
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

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }

    pub fn uptime_seconds(&self) -> u64 {
        time_now().saturating_sub(self.started_at)
    }
}

fn hosts_sync_path(args: &DaemonArgs) -> Option<PathBuf> {
    if !args.hosts_sync {
        return None;
    }

    args.hosts_path.clone().or_else(|| {
        hosts::HostsBuilder::default_path()
            .ok()
            .or_else(|| Some(PathBuf::from("/etc/hosts")))
    })
}
