use std::{collections::BTreeMap, time::Duration};

use anyhow::Result;
use iroh::{EndpointAddr, SecretKey, TransportAddr};
use p2p_ddns::{cli::args::DaemonArgs, net::init_network, storage::Storage};

#[tokio::test]
async fn hosts_sync_writes_and_cleans_managed_section_on_shutdown() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let hosts_path = dir.path().join("hosts");
    std::fs::write(&hosts_path, "127.0.0.1 localhost\n")?;

    let mut args = DaemonArgs::default();
    args.daemon = false;
    args.primary = true;
    args.domain = Some("alpha".to_string());
    args.config = Some(dir.path().to_path_buf());
    args.bind = Some("127.0.0.1:0".to_string());
    args.no_mdns = true;
    args.dht = false;
    args.hosts_sync = true;
    args.hosts_path = Some(hosts_path.clone());
    args.hosts_suffix = Some("p2p".to_string());
    DaemonArgs::validate(&args)?;

    let storage = Storage::new(dir.path().join("storage.db"))?;
    let (ctx, _gos, _sp) = init_network(args, storage).await?;

    let remote_pk = SecretKey::generate(&mut rand::rng()).public();
    ctx.nodes.insert(
        remote_pk,
        p2p_ddns::domain::node::Node {
            node_id: remote_pk,
            invitor: remote_pk,
            addr: EndpointAddr::from_parts(
                remote_pk,
                [TransportAddr::Ip("192.168.50.20:7777".parse().unwrap())],
            ),
            domain: "bravo".to_string(),
            services: BTreeMap::new(),
            last_heartbeat: 1,
        },
    );

    ctx.sync_hosts_file()?;
    let contents = std::fs::read_to_string(&hosts_path)?;
    assert!(contents.contains("# DO NOT EDIT p2p-ddns BEGIN"));
    assert!(contents.contains("alpha alpha.p2p"));
    assert!(contents.contains("bravo bravo.p2p"));

    ctx.graceful_shutdown().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let contents = std::fs::read_to_string(&hosts_path)?;
    assert!(!contents.contains("# DO NOT EDIT p2p-ddns BEGIN"));
    assert!(contents.contains("127.0.0.1 localhost"));

    Ok(())
}
