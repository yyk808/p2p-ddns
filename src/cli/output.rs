use std::{io::IsTerminal, time::SystemTime};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use comfy_table::{
    Attribute, Cell, Color, ContentArrangement, Row, Table, modifiers::UTF8_ROUND_CORNERS,
    presets::UTF8_FULL,
};
use crossterm::terminal;
use iroh::EndpointAddr;
use serde_json::json;

use crate::{
    domain::{
        client::{DaemonStatus, SERVICE_MARKER_CLIENT},
        node::Node,
    },
    net::Context,
    util,
};

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        let m = seconds / 60;
        let s = seconds % 60;
        if s == 0 {
            format!("{}m", m)
        } else {
            format!("{}m {}s", m, s)
        }
    } else if seconds < 86400 {
        let h = seconds / 3600;
        let m = (seconds % 3600) / 60;
        if m == 0 {
            format!("{}h", h)
        } else {
            format!("{}h {}m", h, m)
        }
    } else {
        let d = seconds / 86400;
        let h = (seconds % 86400) / 3600;
        if h == 0 {
            format!("{}d", d)
        } else {
            format!("{}d {}h", d, h)
        }
    }
}

pub fn print(ctx: &Context) {
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut data = ctx
        .nodes
        .iter()
        .map(|r| {
            let node = r.value();
            let addr = util::best_ip_for_display(&node.addr)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let alias = node.domain.clone();
            let last_seen = format!("{} ago", format_duration(now.saturating_sub(node.last_heartbeat)));
            (addr, alias, last_seen)
        })
        .collect::<Vec<_>>();
    data.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));

    log::info!("Known nodes: count={}", data.len());
    for (addr, alias, last_seen) in data {
        log::info!(
            "Node: domain={} addr={} last_seen={}",
            alias,
            addr,
            last_seen
        );
    }
}

fn stdout_supports_color() -> bool {
    std::io::stdout().is_terminal()
}

fn make_table() -> Table {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.apply_modifier(UTF8_ROUND_CORNERS);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table
}

fn styled_cell(value: impl Into<String>, color: Option<Color>, bold: bool) -> Cell {
    let mut cell = Cell::new(value.into());
    if stdout_supports_color() {
        if let Some(color) = color {
            cell = cell.fg(color);
        }
        if bold {
            cell = cell.add_attribute(Attribute::Bold);
        }
    }
    cell
}

fn header_row(columns: impl IntoIterator<Item = &'static str>) -> Row {
    Row::from(
        columns
            .into_iter()
            .map(|value| styled_cell(value, Some(Color::Grey), true))
            .collect::<Vec<_>>(),
    )
}

fn section_title(title: &str) -> String {
    format!("\n{}", colorize(title, Some(Color::Grey), true))
}

fn last_seen_cell(seconds: u64) -> Cell {
    let color = if seconds <= 30 {
        Color::Green
    } else if seconds <= 90 {
        Color::Yellow
    } else {
        Color::Red
    };
    styled_cell(format!("{} ago", format_duration(seconds)), Some(color), false)
}

fn terminal_width() -> Option<usize> {
    if !std::io::stdout().is_terminal() {
        return None;
    }
    terminal::size().ok().map(|(width, _)| width as usize)
}

fn colorize(value: impl Into<String>, color: Option<Color>, bold: bool) -> String {
    let value = value.into();
    if !stdout_supports_color() {
        return value;
    }

    let mut codes = Vec::new();
    if bold {
        codes.push("1");
    }
    if let Some(color) = color {
        let code = match color {
            Color::Black => "30",
            Color::DarkGrey => "90",
            Color::Red | Color::DarkRed => "31",
            Color::Green | Color::DarkGreen => "32",
            Color::Yellow | Color::DarkYellow => "33",
            Color::Blue | Color::DarkBlue => "34",
            Color::Magenta | Color::DarkMagenta => "35",
            Color::Cyan | Color::DarkCyan => "36",
            Color::White | Color::Grey => "37",
            _ => "37",
        };
        codes.push(code);
    }

    if codes.is_empty() {
        value
    } else {
        format!("\x1b[{}m{}\x1b[0m", codes.join(";"), value)
    }
}

fn status_line(
    label: &str,
    value: impl Into<String>,
    color: Option<Color>,
    bold: bool,
) -> (String, String) {
    let value = value.into();
    let plain = format!("{label:18} {value}");
    let rendered = format!(
        "{} {}",
        colorize(format!("{label:18}"), Some(Color::DarkGrey), true),
        colorize(value, color, bold)
    );
    (plain, rendered)
}

fn status_section(title: &str, lines: Vec<(String, String)>) -> Vec<(usize, String)> {
    let title_plain = title.to_string();
    let mut rendered = Vec::with_capacity(lines.len() + 1);
    rendered.push((
        title_plain.len(),
        colorize(title_plain, Some(Color::Grey), true),
    ));
    for (plain, rendered_line) in lines {
        rendered.push((plain.len(), rendered_line));
    }
    rendered
}

fn print_status_sections(left: Vec<(usize, String)>, right: Vec<(usize, String)>) {
    let left_width = left.iter().map(|(len, _)| *len).max().unwrap_or(0);
    let right_width = right.iter().map(|(len, _)| *len).max().unwrap_or(0);
    let separator_plain = " │ ";
    let separator_rendered = colorize(" │ ", Some(Color::DarkGrey), false);
    let needed_width = left_width + separator_plain.len() + right_width;

    if terminal_width().is_some_and(|width| width >= needed_width + 4) {
        let total_rows = left.len().max(right.len());
        println!();
        for idx in 0..total_rows {
            let (left_plain_len, left_rendered) =
                left.get(idx).cloned().unwrap_or_else(|| (0, String::new()));
            let (_, right_rendered) = right
                .get(idx)
                .cloned()
                .unwrap_or_else(|| (0, String::new()));
            let padding = " ".repeat(left_width.saturating_sub(left_plain_len));
            println!("{left_rendered}{padding}{separator_rendered}{right_rendered}");
        }
    } else {
        println!();
        for (_, line) in left {
            println!("{line}");
        }
        println!();
        for (_, line) in right {
            println!("{line}");
        }
    }
}

pub fn display_nodes(nodes: &[Node]) {
    if nodes.is_empty() {
        println!(
            "\n{}",
            colorize("No nodes found in the network.", Some(Color::DarkGrey), false)
        );
        println!(
            "{}",
            colorize(
                "Use 'p2p-ddnsctl node add <ticket>' to add a node.",
                Some(Color::DarkGrey),
                false
            )
        );
        return;
    }

    let now = util::time_now();
    let mut rows = nodes
        .iter()
        .map(|node| {
            let addr = util::best_ip_for_display(&node.addr)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            let role = if node.services.contains_key(SERVICE_MARKER_CLIENT) {
                "Client"
            } else {
                "Daemon"
            };
            let last_seen_seconds = now.saturating_sub(node.last_heartbeat);
            (
                node.domain.clone(),
                addr,
                role.to_string(),
                node.services.len().to_string(),
                last_seen_seconds,
            )
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    println!("{}", section_title("Network Nodes"));
    let mut table = make_table();
    table.set_header(header_row([
        "Name",
        "Address",
        "Role",
        "Services",
        "Last Seen",
    ]));

    for (name, addr, role, service_count, last_seen_seconds) in rows {
        let role_color = if role == "Client" {
            Some(Color::DarkMagenta)
        } else {
            Some(Color::DarkGreen)
        };
        table.add_row(vec![
            styled_cell(name, Some(Color::Grey), true),
            styled_cell(addr, Some(Color::DarkYellow), false),
            styled_cell(role, role_color, true),
            styled_cell(service_count, Some(Color::DarkGrey), false),
            last_seen_cell(last_seen_seconds),
        ]);
    }

    println!("{}", table);
}

pub fn display_status(status: &DaemonStatus) {
    let left = status_section(
        "Daemon Status",
        vec![
            status_line(
                "Running",
                if status.running { "Yes" } else { "No" },
                if status.running {
                    Some(Color::DarkGreen)
                } else {
                    Some(Color::DarkGrey)
                },
                true,
            ),
            status_line(
                "Paused",
                if status.paused { "Yes" } else { "No" },
                if status.paused {
                    Some(Color::DarkYellow)
                } else {
                    Some(Color::DarkGrey)
                },
                true,
            ),
            status_line(
                "Node Count",
                status.node_count.to_string(),
                Some(Color::Grey),
                true,
            ),
            status_line(
                "Client Count",
                status.client_count.to_string(),
                Some(Color::Grey),
                true,
            ),
            status_line(
                "Uptime",
                format_duration(status.uptime_seconds),
                Some(Color::DarkGreen),
                false,
            ),
            status_line(
                "My Domain",
                status.my_domain.clone(),
                Some(Color::Grey),
                true,
            ),
            status_line(
                "My Address",
                status.my_addr.clone(),
                Some(Color::DarkYellow),
                false,
            ),
        ],
    );

    let right = status_section(
        "Hosts Sync",
        vec![
            status_line(
                "Enabled",
                if status.hosts_sync.enabled {
                    "Enabled"
                } else {
                    "Disabled"
                },
                if status.hosts_sync.enabled {
                    Some(Color::DarkGreen)
                } else {
                    Some(Color::DarkGrey)
                },
                true,
            ),
            status_line(
                "Path",
                status
                    .hosts_sync
                    .path
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
                if status.hosts_sync.path.is_some() {
                    Some(Color::Grey)
                } else {
                    Some(Color::DarkGrey)
                },
                false,
            ),
            status_line(
                "Cleanup On Shutdown",
                if status.hosts_sync.cleanup_on_shutdown {
                    "Enabled"
                } else {
                    "Disabled"
                },
                if status.hosts_sync.cleanup_on_shutdown {
                    Some(Color::DarkGreen)
                } else {
                    Some(Color::DarkGrey)
                },
                true,
            ),
            status_line(
                "Last Success",
                status
                    .hosts_sync
                    .last_success
                    .map(|ts| ts.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                if status.hosts_sync.last_success.is_some() {
                    Some(Color::DarkGreen)
                } else {
                    Some(Color::DarkGrey)
                },
                false,
            ),
            status_line(
                "Last Cleanup",
                status
                    .hosts_sync
                    .last_cleanup
                    .map(|ts| ts.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                if status.hosts_sync.last_cleanup.is_some() {
                    Some(Color::Grey)
                } else {
                    Some(Color::DarkGrey)
                },
                false,
            ),
            status_line(
                "Last Error",
                status
                    .hosts_sync
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
                if status.hosts_sync.last_error.is_some() {
                    Some(Color::DarkRed)
                } else {
                    Some(Color::DarkGrey)
                },
                false,
            ),
        ],
    );

    print_status_sections(left, right);
}

pub fn display_ticket(ticket: &str) {
    println!("{}", section_title("Bootstrap Ticket"));
    let mut table = make_table();
    table.set_header(header_row(["Field", "Value"]));
    table.add_row(vec![
        styled_cell("Ticket", Some(Color::Grey), true),
        styled_cell(ticket.to_string(), Some(Color::DarkGreen), false),
    ]);
    println!("{}", table);
    println!("Use this ticket when adding another node to the network.");
}

pub fn display_ack(message: &str) {
    println!("\n{}", colorize(message, Some(Color::Green), true));
}

pub fn display_info(message: &str) {
    println!("{}", colorize(message, Some(Color::DarkGrey), false));
}

pub fn display_error(message: &str) {
    eprintln!("\n{}", colorize(format!("Error: {}", message), Some(Color::Red), true));
}

// --- JSON output functions ---

fn node_to_json(node: &Node) -> serde_json::Value {
    let addr = util::best_ip_for_display(&node.addr)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let role = if node.services.contains_key(SERVICE_MARKER_CLIENT) {
        "Client"
    } else {
        "Daemon"
    };
    json!({
        "node_id": node.node_id.to_string(),
        "domain": node.domain,
        "address": addr,
        "role": role,
        "services": node.services,
        "last_heartbeat": node.last_heartbeat,
    })
}

pub fn display_nodes_json(nodes: &[Node]) {
    let nodes_json: Vec<serde_json::Value> = nodes.iter().map(node_to_json).collect();
    let output = json!({ "nodes": nodes_json, "count": nodes.len() });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

pub fn display_status_json(status: &DaemonStatus) {
    let output = json!({
        "running": status.running,
        "paused": status.paused,
        "node_count": status.node_count,
        "client_count": status.client_count,
        "uptime_seconds": status.uptime_seconds,
        "my_domain": status.my_domain,
        "my_addr": status.my_addr,
        "hosts_sync": {
            "enabled": status.hosts_sync.enabled,
            "path": status.hosts_sync.path,
            "cleanup_on_shutdown": status.hosts_sync.cleanup_on_shutdown,
            "last_success": status.hosts_sync.last_success,
            "last_cleanup": status.hosts_sync.last_cleanup,
            "last_error": status.hosts_sync.last_error,
        }
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

pub fn display_ticket_json(ticket: &str) {
    let output = json!({ "ticket": ticket });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

pub fn display_ack_json(message: &str) {
    let output = json!({ "ok": true, "message": message });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

pub fn display_error_json(error: &str) {
    let output = json!({ "ok": false, "error": error });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
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

pub fn print_bootstrap_ticket(ctx: &Context) {
    if ctx.args.primary {
        println!("Ticket (raw): {}", ctx.ticket);
        println!("Share this ticket with other nodes so they can join the network.");
    }
}
