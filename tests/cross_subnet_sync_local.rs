use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use p2p_ddns::{
    cli::args::{DaemonArgs, LogLevel},
    net::init_network,
    storage::Storage,
};
use tempfile::tempdir;

fn make_args(name: &str, primary: bool, ticket: Option<String>, port: u16) -> DaemonArgs {
    DaemonArgs {
        daemon: true,
        primary,
        domain: Some(name.to_string()),
        ticket,
        log: LogLevel::Info,
        bind: Some(format!("127.0.0.1:{port}")),
        no_mdns: true,
        dht: false,
        ..DaemonArgs::default()
    }
}

async fn make_storage() -> Result<Storage> {
    let dir = tempdir()?;
    let db_path = dir.path().join("storage.db");
    // Keep the tempdir alive by leaking it for the duration of the test.
    std::mem::forget(dir);
    Storage::new(db_path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cross_subnet_like_sync_learns_all_ips() -> Result<()> {
    // Primary A
    let storage_a = make_storage().await?;
    let args_a = make_args("a", true, None, 18080);
    let (ctx_a, gos_a, sp_a) = init_network(args_a, storage_a).await?;
    let ticket_a = ctx_a.ticket.to_string();
    let ctx_a = Arc::new(ctx_a);

    // B joins via A's ticket
    let storage_b = make_storage().await?;
    let args_b = make_args("b", false, Some(ticket_a), 18081);
    let (ctx_b, gos_b, sp_b) = init_network(args_b, storage_b).await?;
    let ticket_b = ctx_b.ticket.to_string();
    let ctx_b = Arc::new(ctx_b);

    // C joins via B's ticket (simulates a "different subnet" only reachable via known node)
    let storage_c = make_storage().await?;
    let args_c = make_args("c", false, Some(ticket_b), 18082);
    let (ctx_c, gos_c, sp_c) = init_network(args_c, storage_c).await?;
    let ctx_c = Arc::new(ctx_c);

    let node_a = ctx_a.me.node_id;
    let node_b = ctx_b.me.node_id;
    let node_c = ctx_c.me.node_id;

    let h_a = {
        let ctx = ctx_a.clone();
        tokio::spawn(async move { ctx.run_for(gos_a, sp_a, Duration::from_secs(10)).await })
    };
    let h_b = {
        let ctx = ctx_b.clone();
        tokio::spawn(async move { ctx.run_for(gos_b, sp_b, Duration::from_secs(10)).await })
    };
    let h_c = {
        let ctx = ctx_c.clone();
        tokio::spawn(async move { ctx.run_for(gos_c, sp_c, Duration::from_secs(10)).await })
    };

    let _ = tokio::join!(h_a, h_b, h_c);

    fn has_any_advertised_addr(
        learned: &p2p_ddns::domain::node::Node,
        advertised: &[SocketAddr],
    ) -> bool {
        learned
            .addr
            .ip_addrs()
            .any(|a| advertised.iter().any(|b| b == a))
    }

    // Each node should learn about the other nodes and have usable IP addresses for them.
    let advertised_a: Vec<SocketAddr> = ctx_a.handle.addr().ip_addrs().copied().collect();
    let advertised_b: Vec<SocketAddr> = ctx_b.handle.addr().ip_addrs().copied().collect();
    let advertised_c: Vec<SocketAddr> = ctx_c.handle.addr().ip_addrs().copied().collect();

    let b_from_a = ctx_a.nodes.get(&node_b).expect("A should learn B");
    assert!(
        has_any_advertised_addr(&b_from_a, &advertised_b),
        "A learned B but addr={:?}, expected one of {:?}",
        b_from_a.addr,
        advertised_b
    );
    let c_from_a = ctx_a.nodes.get(&node_c).expect("A should learn C");
    assert!(
        has_any_advertised_addr(&c_from_a, &advertised_c),
        "A learned C but addr={:?}, expected one of {:?}",
        c_from_a.addr,
        advertised_c
    );

    let a_from_b = ctx_b.nodes.get(&node_a).expect("B should learn A");
    assert!(
        has_any_advertised_addr(&a_from_b, &advertised_a),
        "B learned A but addr={:?}, expected one of {:?}",
        a_from_b.addr,
        advertised_a
    );
    let c_from_b = ctx_b.nodes.get(&node_c).expect("B should learn C");
    assert!(
        has_any_advertised_addr(&c_from_b, &advertised_c),
        "B learned C but addr={:?}, expected one of {:?}",
        c_from_b.addr,
        advertised_c
    );

    let a_from_c = ctx_c.nodes.get(&node_a).expect("C should learn A");
    assert!(
        has_any_advertised_addr(&a_from_c, &advertised_a),
        "C learned A but addr={:?}, expected one of {:?}",
        a_from_c.addr,
        advertised_a
    );
    let b_from_c = ctx_c.nodes.get(&node_b).expect("C should learn B");
    assert!(
        has_any_advertised_addr(&b_from_c, &advertised_b),
        "C learned B but addr={:?}, expected one of {:?}",
        b_from_c.addr,
        advertised_b
    );

    Ok(())
}
