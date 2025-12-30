use std::sync::Arc;

use anyhow::Result;
use base64::Engine as _;
use iroh::SecretKey;
use p2p_ddns::{
    admin::{authz::ClientRegistry, handler, protocol::*},
    cli::args::DaemonArgs,
    domain::{node::Node, ticket::Ticket},
    net::init_network,
    storage::Storage,
};
use tempfile::tempdir;

async fn make_context() -> Result<(p2p_ddns::net::Context, Arc<ClientRegistry>)> {
    let dir = tempdir()?;
    let mut args = DaemonArgs::default();
    args.daemon = true;
    args.primary = true;
    args.domain = Some("a".to_string());
    args.config = Some(dir.path().to_path_buf());
    args.bind = Some("127.0.0.1:0".to_string());
    args.no_mdns = true;
    args.dht = false;
    DaemonArgs::validate(&args)?;

    let storage = Storage::new(dir.path().join("storage.db"))?;
    let (ctx, _gos, _sp) = init_network(args, storage).await?;
    Ok((ctx, Arc::new(ClientRegistry::new())))
}

#[tokio::test]
async fn auth_rejects_invalid_ticket() -> Result<()> {
    let (ctx, clients) = make_context().await?;

    let auth_req = AuthRequest {
        ticket: "definitely-not-a-ticket".to_string(),
        client_public_key: None,
        client_name: None,
    };

    let (resp, id) = handler::authenticate_and_register(&ctx, &clients, &auth_req)?;
    assert!(!resp.success);
    assert!(id.is_none());
    Ok(())
}

#[tokio::test]
async fn auth_registers_client_and_query_excludes_client_nodes() -> Result<()> {
    let (ctx, clients) = make_context().await?;

    let mut rng = rand::rng();
    let sk = SecretKey::generate(&mut rng);
    let pk = sk.public();
    let pk_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(pk.as_bytes());

    let auth_req = AuthRequest {
        ticket: ctx.ticket.to_string(),
        client_public_key: Some(pk_b64),
        client_name: Some("cli".to_string()),
    };

    let (resp, id) = handler::authenticate_and_register(&ctx, &clients, &auth_req)?;
    assert!(resp.success);
    let id = id.expect("client id");
    assert_eq!(id, pk);
    assert!(clients.is_client_node(&id));
    assert!(ctx.nodes.contains_key(&id));

    let outcome = handler::handle_command(&ClientCommand::Query, &ctx, &clients).await;
    let nodes = match outcome.response {
        ClientResponse::Nodes(nodes) => nodes,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    assert!(
        !nodes.iter().any(|n| n.node_id == id),
        "query should exclude client nodes"
    );

    Ok(())
}

#[tokio::test]
async fn shutdown_maps_to_action_in_handler() -> Result<()> {
    let (ctx, clients) = make_context().await?;

    let outcome = handler::handle_command(&ClientCommand::Shutdown, &ctx, &clients).await;
    assert!(matches!(
        outcome.action,
        Some(handler::AdminAction::Shutdown)
    ));
    Ok(())
}

#[tokio::test]
async fn pause_and_resume_affect_status() -> Result<()> {
    let (ctx, clients) = make_context().await?;

    let _ = handler::handle_command(&ClientCommand::Pause, &ctx, &clients).await;
    let status = match handler::handle_command(&ClientCommand::Status, &ctx, &clients)
        .await
        .response
    {
        ClientResponse::Status(s) => s,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    assert!(status.paused);

    let _ = handler::handle_command(&ClientCommand::Resume, &ctx, &clients).await;
    let status = match handler::handle_command(&ClientCommand::Status, &ctx, &clients)
        .await
        .response
    {
        ClientResponse::Status(s) => s,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    assert!(!status.paused);

    Ok(())
}

#[tokio::test]
async fn add_node_and_remove_node_persist_and_update_state() -> Result<()> {
    let (ctx, clients) = make_context().await?;

    let mut rng = rand::rng();
    let pk = SecretKey::generate(&mut rng).public();
    let node = Node {
        node_id: pk,
        invitor: pk,
        addr: iroh::EndpointAddr::new(pk),
        domain: "added".to_string(),
        services: Default::default(),
        last_heartbeat: 1,
    };

    let ticket = Ticket::new(Some(ctx.ticket.topic()), node).to_string();
    let outcome = handler::handle_command(&ClientCommand::AddNode { ticket }, &ctx, &clients).await;
    assert!(matches!(outcome.response, ClientResponse::Ack));
    assert!(ctx.nodes.contains_key(&pk));

    let outcome = handler::handle_command(
        &ClientCommand::RemoveNode { id: pk.to_string() },
        &ctx,
        &clients,
    )
    .await;
    assert!(matches!(outcome.response, ClientResponse::Ack));
    assert!(!ctx.nodes.contains_key(&pk));

    Ok(())
}
