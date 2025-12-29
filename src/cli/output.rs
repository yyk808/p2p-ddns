use std::time::SystemTime;

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
