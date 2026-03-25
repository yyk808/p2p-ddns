use std::time::SystemTime;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use iroh::EndpointAddr;

use crate::{net::Context, util};

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;

    format!("{}Hour {}Min {}Sec ago", hours, minutes, seconds)
}

pub fn print(ctx: &Context) {
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let data = ctx
        .nodes
        .iter()
        .map(|r| {
            let node = r.value();
            let addr = util::best_ip_for_display(&node.addr)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let alias = node.domain.clone();
            let last_seen = format_duration(now.saturating_sub(node.last_heartbeat));
            (addr, alias, last_seen)
        })
        .collect::<Vec<_>>();

    let mut builder = tabled::builder::Builder::default();
    builder.push_record(["Address", "Name", "Last Seen"]);
    for (addr, alias, last_seen) in data {
        builder.push_record([addr, alias, last_seen]);
    }
    let table = builder.build();
    println!("{}", table);
}

fn format_endpoint_addr(addr: &EndpointAddr) -> String {
    let mut parts = Vec::new();

    let relays: Vec<String> = addr.relay_urls().map(|u| u.to_string()).collect();
    if !relays.is_empty() {
        parts.push(format!("relays=[{}]", relays.join(", ")));
    }

    let ips: Vec<String> = addr.ip_addrs().map(|s| s.to_string()).collect();
    if !ips.is_empty() {
        parts.push(format!("ips=[{}]", ips.join(", ")));
    }

    if parts.is_empty() {
        "<empty>".to_string()
    } else {
        parts.join(" ")
    }
}

pub fn log_startup(ctx: &Context) {
    let (topic, rnum, invitor) = ctx.ticket.flatten();
    let rnum_b64 = STANDARD_NO_PAD.encode(&rnum);

    log::info!(
        "Startup: primary={} daemon={} mdns={} dht={} relay_mode={} relay_urls={}",
        ctx.args.primary,
        ctx.args.daemon,
        !ctx.args.no_mdns,
        ctx.args.dht,
        ctx.args.relay_mode,
        if ctx.args.relay_url.is_empty() {
            "<none>".to_string()
        } else {
            ctx.args.relay_url.join(",")
        }
    );

    log::info!("Me: node_id={} domain={}", ctx.me.node_id, ctx.me.domain);
    log::info!(
        "Me: endpoint_addr={}",
        format_endpoint_addr(&ctx.handle.addr())
    );
    log::info!("Me: advertised_addr={}", format_endpoint_addr(&ctx.me.addr));

    log::info!(
        "Ticket: topic={topic:?} rnum_b64={rnum_b64} invitor_node_id={} invitor_addr={}",
        invitor.node_id,
        format_endpoint_addr(&invitor.addr)
    );
    log::info!("Ticket (raw): {}", ctx.ticket);
}
