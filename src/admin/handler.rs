use std::collections::BTreeMap;

use anyhow::Result;
use base64::Engine as _;
use iroh::{EndpointAddr, EndpointId, PublicKey};

use crate::{
    admin::{authz::ClientRegistry, protocol::*},
    domain::{
        client::{ClientInfo, ClientPermissions, SERVICE_MARKER_CLIENT, SERVICE_VALUE_CLIENT},
        message::Message,
        node::Node,
        ticket::Ticket,
    },
    net::Context,
    util,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAction {
    Shutdown,
}

#[derive(Debug)]
pub struct CommandOutcome {
    pub response: ClientResponse,
    pub action: Option<AdminAction>,
}

pub fn authenticate_and_register(
    ctx: &Context,
    clients: &ClientRegistry,
    auth_req: &AuthRequest,
) -> Result<(AuthResponse, Option<EndpointId>)> {
    let ticket_valid = match auth_req.ticket.parse::<Ticket>() {
        Ok(ticket) => ticket.validate(ctx.ticket.topic(), ctx.ticket.rnum()),
        Err(_) => false,
    };

    if !ticket_valid {
        return Ok((
            AuthResponse {
                success: false,
                error: Some("Invalid ticket".to_string()),
                daemon_public_key: None,
            },
            None,
        ));
    }

    let client_pk = match auth_req.client_public_key.as_deref() {
        Some(pk_str) => match base64::engine::general_purpose::STANDARD_NO_PAD.decode(pk_str) {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(bytes) => PublicKey::from_bytes(&bytes).ok(),
                Err(_) => None,
            },
            Err(_) => None,
        },
        None => None,
    };

    if let Some(pk) = client_pk {
        if clients.is_client_node(&pk) {
            return Ok((
                AuthResponse {
                    success: true,
                    error: None,
                    daemon_public_key: Some(
                        base64::engine::general_purpose::STANDARD_NO_PAD
                            .encode(ctx.me.node_id.as_bytes()),
                    ),
                },
                Some(pk as EndpointId),
            ));
        }

        let client_node = Node {
            node_id: pk,
            invitor: ctx.me.node_id,
            addr: EndpointAddr::new(pk),
            domain: auth_req
                .client_name
                .clone()
                .unwrap_or_else(|| format!("client-{}", pk)),
            services: {
                let mut map = BTreeMap::new();
                map.insert(SERVICE_MARKER_CLIENT.to_string(), SERVICE_VALUE_CLIENT);
                map
            },
            last_heartbeat: util::time_now(),
        };

        ctx.nodes.insert(pk, client_node);

        let client_info = ClientInfo {
            connected_at: util::time_now(),
            ticket_used: auth_req.ticket.clone(),
            client_name: auth_req.client_name.clone(),
            permissions: ClientPermissions {
                can_query: true,
                can_add_node: true,
                can_remove_node: true,
                can_control: true,
            },
        };
        clients.add_client(pk, client_info);

        let introduce_msg = Message::Introduce { invited: pk };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = ctx.broadcast_message(introduce_msg).await;
        });
    }

    Ok((
        AuthResponse {
            success: true,
            error: None,
            daemon_public_key: Some(
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(ctx.me.node_id.as_bytes()),
            ),
        },
        client_pk.map(|pk| pk as EndpointId),
    ))
}

pub fn required_permission(cmd: &ClientCommand) -> &'static str {
    match cmd {
        ClientCommand::Query => "query",
        ClientCommand::AddNode { .. } => "add_node",
        ClientCommand::RemoveNode { .. } => "remove_node",
        ClientCommand::Status => "query",
        ClientCommand::GetTicket => "query",
        ClientCommand::Pause => "control",
        ClientCommand::Resume => "control",
        ClientCommand::Shutdown => "control",
    }
}

pub async fn handle_command(
    cmd: &ClientCommand,
    ctx: &Context,
    clients: &ClientRegistry,
) -> CommandOutcome {
    match cmd {
        ClientCommand::Query => {
            let nodes = ctx
                .nodes
                .iter()
                .filter(|e| !clients.is_client_node(e.key()))
                .map(|e| e.value().clone())
                .collect();
            CommandOutcome {
                response: ClientResponse::Nodes(nodes),
                action: None,
            }
        }
        ClientCommand::AddNode { ticket } => {
            let parsed: Ticket = match ticket.parse() {
                Ok(t) => t,
                Err(e) => {
                    return CommandOutcome {
                        response: ClientResponse::Error(format!("Invalid ticket: {e}")),
                        action: None,
                    };
                }
            };

            let (topic, _rnum, node) = parsed.flatten();
            if topic != ctx.ticket.topic() {
                return CommandOutcome {
                    response: ClientResponse::Error(
                        "Ticket topic does not match this daemon's network".to_string(),
                    ),
                    action: None,
                };
            }

            ctx.static_provider.add_endpoint_info(node.addr.clone());
            ctx.nodes.insert(node.node_id, node.clone());
            if let Err(e) = ctx.storage.save_node(&node) {
                return CommandOutcome {
                    response: ClientResponse::Error(format!("Failed to persist node: {e}")),
                    action: None,
                };
            }

            CommandOutcome {
                response: ClientResponse::Ack,
                action: None,
            }
        }
        ClientCommand::RemoveNode { id } => {
            let node_id: EndpointId = match id.parse() {
                Ok(id) => id,
                Err(e) => {
                    return CommandOutcome {
                        response: ClientResponse::Error(format!("Invalid node id: {e}")),
                        action: None,
                    };
                }
            };

            if node_id == ctx.me.node_id {
                return CommandOutcome {
                    response: ClientResponse::Error("Refusing to remove self".to_string()),
                    action: None,
                };
            }

            clients.remove_client(&node_id);
            ctx.nodes.remove(&node_id);
            if let Err(e) = ctx.storage.remove_node(&node_id) {
                return CommandOutcome {
                    response: ClientResponse::Error(format!("Failed to remove from storage: {e}")),
                    action: None,
                };
            }

            CommandOutcome {
                response: ClientResponse::Ack,
                action: None,
            }
        }
        ClientCommand::Status => {
            let my_addr = util::best_ip_for_display(&ctx.handle.addr())
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| format!("{:?}", ctx.handle.addr()));
            let status = crate::domain::client::DaemonStatus {
                running: true,
                paused: ctx.is_paused(),
                node_count: ctx.nodes.len(),
                client_count: clients.count(),
                uptime_seconds: ctx.uptime_seconds(),
                my_domain: ctx.me.domain.clone(),
                my_addr,
            };
            CommandOutcome {
                response: ClientResponse::Status(status),
                action: None,
            }
        }
        ClientCommand::GetTicket => CommandOutcome {
            response: ClientResponse::Ticket(ctx.ticket.to_string()),
            action: None,
        },
        ClientCommand::Pause => {
            ctx.set_paused(true);
            CommandOutcome {
                response: ClientResponse::Ack,
                action: None,
            }
        }
        ClientCommand::Resume => {
            ctx.set_paused(false);
            CommandOutcome {
                response: ClientResponse::Ack,
                action: None,
            }
        }
        ClientCommand::Shutdown => CommandOutcome {
            response: ClientResponse::Ack,
            action: Some(AdminAction::Shutdown),
        },
    }
}
