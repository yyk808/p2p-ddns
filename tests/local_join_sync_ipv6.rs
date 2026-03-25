use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::Result;
use iroh::SecretKey;
use p2p_ddns::{cli::args::DaemonArgs, net::init_network, storage::Storage};

#[tokio::test]
async fn local_join_sync_over_ipv6_loopback() -> Result<()> {
    let dir_a = tempfile::tempdir()?;
    let dir_b = tempfile::tempdir()?;

    let args_a = DaemonArgs {
        daemon: false,
        primary: true,
        domain: Some("a6".to_string()),
        config: Some(dir_a.path().to_path_buf()),
        bind: Some("[::1]:0".to_string()),
        no_mdns: true,
        dht: false,
        ..DaemonArgs::default()
    };
    DaemonArgs::validate(&args_a)?;

    let storage_a = Storage::new(dir_a.path().join("storage.db"))?;
    let (ctx_a, gos_a, sp_a) = init_network(args_a, storage_a).await?;
    let ticket = ctx_a.ticket.to_string();

    let args_b = DaemonArgs {
        daemon: false,
        primary: false,
        domain: Some("b6".to_string()),
        ticket: Some(ticket),
        config: Some(dir_b.path().to_path_buf()),
        bind: Some("[::1]:0".to_string()),
        no_mdns: true,
        dht: false,
        ..DaemonArgs::default()
    };
    DaemonArgs::validate(&args_b)?;

    let storage_b = Storage::new(dir_b.path().join("storage.db"))?;
    let (ctx_b, gos_b, sp_b) = init_network(args_b, storage_b).await?;

    let id_a = ctx_a.me.node_id;
    let id_b = ctx_b.me.node_id;
    let rnum_b = ctx_b.ticket.rnum();

    let ctx_a = Arc::new(ctx_a);
    let ctx_b = Arc::new(ctx_b);

    let task_a = {
        let ctx_a = ctx_a.clone();
        tokio::spawn(async move { ctx_a.run_for(gos_a, sp_a, Duration::from_secs(3)).await })
    };
    let task_b = {
        let ctx_b = ctx_b.clone();
        tokio::spawn(async move { ctx_b.run_for(gos_b, sp_b, Duration::from_secs(3)).await })
    };

    ctx_b
        .send_message_to(
            &id_a,
            p2p_ddns::domain::message::Message::Invited {
                topic: ctx_a.ticket.topic(),
                rnum: rnum_b,
                addr: ctx_b.handle.addr(),
                alias: ctx_b.me.domain.clone(),
                services: BTreeMap::new(),
                invitor: ctx_b.me.invitor,
            },
        )
        .await?;

    tokio::time::timeout(Duration::from_secs(2), async {
        while !ctx_a.nodes.contains_key(&id_b) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;

    let joined = ctx_a.nodes.get(&id_b).expect("joined node");
    assert_eq!(joined.invitor, id_a);

    let mut rng = rand::rng();
    let pk_d = SecretKey::generate(&mut rng).public();
    let node_d = p2p_ddns::domain::node::Node {
        node_id: pk_d,
        invitor: pk_d,
        addr: iroh::EndpointAddr::new(pk_d),
        domain: "d6".to_string(),
        services: BTreeMap::new(),
        last_heartbeat: 1,
    };
    ctx_a
        .send_message_to(
            &id_b,
            p2p_ddns::domain::message::Message::SyncRequest {
                nodes: vec![node_d.clone()],
            },
        )
        .await?;

    tokio::time::timeout(Duration::from_secs(2), async {
        while !ctx_b.nodes.contains_key(&node_d.node_id) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;

    let _ = task_a.await;
    let _ = task_b.await;

    assert!(ctx_b.nodes.contains_key(&id_a));
    Ok(())
}
