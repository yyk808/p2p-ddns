use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::Result;
use iroh::{EndpointAddr, TransportAddr};
use netdev::interface::get_interfaces;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindTarget {
    Ip(IpAddr),
    Socket(SocketAddr),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterfaceAddrs {
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<(Ipv6Addr, u32)>,
}

const LOCAL_ONLY_INTERFACE_EXACT_NAMES: &[&str] = &[
    "lo",
    "lo0",
    "kube-ipvs0",
    "cilium_host",
    "cilium_net",
    "cilium_vxlan",
];

const LOCAL_ONLY_INTERFACE_PREFIXES: &[&str] = &[
    "docker", "br-", "veth", "cni", "flannel", "virbr", "podman", "lxcbr", "vboxnet", "vmnet",
];

pub fn time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn parse_bind_addr(bind: &str) -> Result<SocketAddr> {
    Ok(bind.parse::<SocketAddr>()?)
}

pub fn parse_bind_target(bind: &str) -> Result<BindTarget> {
    if let Ok(addr) = bind.parse::<SocketAddr>() {
        return Ok(BindTarget::Socket(addr));
    }
    if let Ok(ip) = bind.parse::<IpAddr>() {
        return Ok(BindTarget::Ip(ip));
    }
    if bind.starts_with('[') && bind.ends_with(']') {
        let inner = &bind[1..bind.len() - 1];
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Ok(BindTarget::Ip(ip));
        }
    }
    anyhow::bail!("invalid bind value `{bind}`; expected IP or IP:PORT");
}

pub fn lookup_interface_addrs(name: &str) -> Result<InterfaceAddrs> {
    let iface = get_interfaces()
        .into_iter()
        .find(|iface| iface.name == name || iface.friendly_name.as_deref() == Some(name))
        .ok_or_else(|| anyhow::anyhow!("network interface `{name}` not found"))?;

    let mut addrs = InterfaceAddrs {
        v4: iface.ipv4.iter().map(|net| net.addr()).collect(),
        v6: iface
            .ipv6
            .iter()
            .enumerate()
            .map(|(idx, net)| {
                let scope_id = iface
                    .ipv6_scope_ids
                    .get(idx)
                    .copied()
                    .unwrap_or(iface.index);
                (net.addr(), scope_id)
            })
            .collect(),
    };

    addrs.v4.sort_unstable();
    addrs.v4.dedup();
    addrs.v6.sort_unstable();
    addrs.v6.dedup();

    if addrs.v4.is_empty() && addrs.v6.is_empty() {
        anyhow::bail!("network interface `{name}` has no IP addresses");
    }

    Ok(addrs)
}

pub fn is_local_only_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }

    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    }
}

fn is_local_only_interface_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    LOCAL_ONLY_INTERFACE_EXACT_NAMES.contains(&lower.as_str())
        || LOCAL_ONLY_INTERFACE_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

fn local_only_interface_ip_map() -> HashMap<IpAddr, bool> {
    let mut out = HashMap::new();

    for iface in get_interfaces() {
        let local_only = iface.is_loopback()
            || !iface.is_up()
            || is_local_only_interface_name(&iface.name)
            || iface
                .friendly_name
                .as_deref()
                .is_some_and(is_local_only_interface_name);

        for ip in iface
            .ipv4
            .iter()
            .map(|net| IpAddr::V4(net.addr()))
            .chain(iface.ipv6.iter().map(|net| IpAddr::V6(net.addr())))
        {
            out.entry(ip)
                .and_modify(|current| *current &= local_only)
                .or_insert(local_only);
        }
    }

    out
}

fn filter_advertisable_endpoint_addr_with_map(
    addr: &EndpointAddr,
    local_only_ip_map: &HashMap<IpAddr, bool>,
) -> EndpointAddr {
    EndpointAddr::from_parts(
        addr.id,
        addr.relay_urls().cloned().map(TransportAddr::Relay).chain(
            addr.ip_addrs().copied().filter_map(|sock| {
                (!is_local_only_ip(sock.ip())
                    && !local_only_ip_map.get(&sock.ip()).copied().unwrap_or(false))
                .then_some(TransportAddr::Ip(sock))
            }),
        ),
    )
}

pub fn filter_advertisable_endpoint_addr(addr: &EndpointAddr) -> EndpointAddr {
    let local_only_ip_map = local_only_interface_ip_map();
    filter_advertisable_endpoint_addr_with_map(addr, &local_only_ip_map)
}

pub fn best_ip_for_display(addr: &EndpointAddr) -> Option<IpAddr> {
    let mut best_v6: Option<IpAddr> = None;
    for sock in addr.ip_addrs() {
        let ip = sock.ip();
        if is_local_only_ip(ip) {
            continue;
        }

        if ip.is_ipv4() {
            return Some(ip);
        }

        if best_v6.is_none() {
            best_v6 = Some(ip);
        }
    }
    best_v6
}

fn common_prefix_bits(a: IpAddr, b: IpAddr) -> u32 {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let a = u32::from_be_bytes(a.octets());
            let b = u32::from_be_bytes(b.octets());
            (a ^ b).leading_zeros()
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let a = u128::from_be_bytes(a.octets());
            let b = u128::from_be_bytes(b.octets());
            (a ^ b).leading_zeros()
        }
        _ => 0,
    }
}

fn best_prefix_score(ip: IpAddr, locals: &[IpAddr]) -> u32 {
    locals
        .iter()
        .map(|local| common_prefix_bits(ip, *local))
        .max()
        .unwrap_or(0)
}

/// Picks the best single IP transport address from `remote` for `local` (by longest common prefix).
///
/// `EndpointAddr` stores transport addresses in a `BTreeSet`, so address ordering is not stable.
/// Selecting a single best address avoids accidentally dialing an unreachable one first.
pub fn best_endpoint_addr_for_local(remote: &EndpointAddr, local: &EndpointAddr) -> EndpointAddr {
    let all_local_ips: Vec<IpAddr> = local.ip_addrs().map(|sock| sock.ip()).collect();
    if all_local_ips.is_empty() {
        return remote.clone();
    }
    let local_ips: Vec<IpAddr> = all_local_ips
        .iter()
        .copied()
        .filter(|ip| !is_local_only_ip(*ip))
        .collect();
    let local_only_mode = local_ips.is_empty();
    let local_ips = if local_only_mode {
        all_local_ips
    } else {
        local_ips
    };
    let local_has_v4 = local_ips.iter().any(|ip| ip.is_ipv4());
    let local_has_v6 = local_ips.iter().any(|ip| ip.is_ipv6());
    let prefer_v4 = local_has_v4 || !local_has_v6;

    let mut best: Option<(u32, bool, SocketAddr)> = None;
    for sock in remote.ip_addrs() {
        if !local_only_mode && is_local_only_ip(sock.ip()) {
            continue;
        }
        let score = best_prefix_score(sock.ip(), &local_ips);
        let is_v4 = sock.ip().is_ipv4();
        let candidate = (score, is_v4, *sock);
        if let Some(current) = best {
            let better_family = if prefer_v4 {
                candidate.1 && !current.1
            } else {
                !candidate.1 && current.1
            };
            if candidate.0 > current.0 || (candidate.0 == current.0 && better_family) {
                best = Some(candidate);
            }
        } else {
            best = Some(candidate);
        }
    }

    let Some((_, _, best_sock)) = best else {
        return remote.clone();
    };
    EndpointAddr::from_parts(remote.id, [TransportAddr::Ip(best_sock)])
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use anyhow::Result;
    use iroh::{EndpointAddr, SecretKey, TransportAddr};

    use super::*;

    #[test]
    fn parse_bind_addr_accepts_ipv4_and_ipv6() -> Result<()> {
        parse_bind_addr("127.0.0.1:1234")?;
        parse_bind_addr("[::1]:1234")?;
        Ok(())
    }

    #[test]
    fn parse_bind_target_accepts_ip_and_socket() -> Result<()> {
        assert_eq!(
            parse_bind_target("127.0.0.1")?,
            BindTarget::Ip("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            parse_bind_target("127.0.0.1:1234")?,
            BindTarget::Socket("127.0.0.1:1234".parse().unwrap())
        );
        assert_eq!(
            parse_bind_target("[::1]")?,
            BindTarget::Ip("::1".parse().unwrap())
        );
        assert_eq!(
            parse_bind_target("[::1]:1234")?,
            BindTarget::Socket("[::1]:1234".parse().unwrap())
        );
        Ok(())
    }

    #[test]
    fn local_only_ip_detection_covers_loopback_and_link_local() {
        assert!(is_local_only_ip("127.0.0.1".parse().unwrap()));
        assert!(is_local_only_ip("169.254.1.10".parse().unwrap()));
        assert!(is_local_only_ip("fe80::1".parse().unwrap()));
        assert!(!is_local_only_ip("10.0.0.10".parse().unwrap()));
        assert!(!is_local_only_ip("fd00::1".parse().unwrap()));
    }

    #[test]
    fn local_only_interface_name_detection_covers_common_virtual_bridges() {
        assert!(is_local_only_interface_name("docker0"));
        assert!(is_local_only_interface_name("br-123456"));
        assert!(is_local_only_interface_name("vethabc123"));
        assert!(is_local_only_interface_name("Virbr0"));
        assert!(!is_local_only_interface_name("eth0"));
        assert!(!is_local_only_interface_name("en0"));
    }

    #[test]
    fn filter_advertisable_endpoint_addr_drops_local_only_ips() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();
        let addr = EndpointAddr::from_parts(
            pk,
            [
                TransportAddr::Ip("172.17.0.1:7777".parse().unwrap()),
                TransportAddr::Ip("169.254.1.10:7777".parse().unwrap()),
                TransportAddr::Ip("127.0.0.1:7777".parse().unwrap()),
            ],
        );

        let filtered = filter_advertisable_endpoint_addr_with_map(
            &addr,
            &HashMap::from([("172.17.0.1".parse().unwrap(), true)]),
        );
        let ips = filtered.ip_addrs().copied().collect::<Vec<_>>();
        assert!(ips.is_empty());
    }

    #[test]
    fn best_ip_for_display_prefers_ipv4_then_ipv6() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let v4: SocketAddr = "203.0.113.1:1".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:1".parse().unwrap();

        let addr = EndpointAddr::from_parts(pk, [TransportAddr::Ip(v6), TransportAddr::Ip(v4)]);
        assert_eq!(best_ip_for_display(&addr), Some(v4.ip()));
    }

    #[test]
    fn best_ip_for_display_uses_ipv6_when_no_ipv4() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let v6: SocketAddr = "[2001:db8::2]:1".parse().unwrap();
        let addr = EndpointAddr::from_parts(pk, [TransportAddr::Ip(v6)]);
        assert_eq!(best_ip_for_display(&addr), Some(v6.ip()));
    }

    #[test]
    fn order_endpoint_addr_for_local_prefers_longest_common_prefix() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let local: SocketAddr = "192.168.158.9:7777".parse().unwrap();
        let remote_a: SocketAddr = "192.168.156.2:7777".parse().unwrap();
        let remote_b: SocketAddr = "192.168.158.2:7777".parse().unwrap();

        let local = EndpointAddr::from_parts(pk, [TransportAddr::Ip(local)]);
        let remote = EndpointAddr::from_parts(
            pk,
            [TransportAddr::Ip(remote_a), TransportAddr::Ip(remote_b)],
        );

        let best = best_endpoint_addr_for_local(&remote, &local);
        let ips = best.ip_addrs().copied().collect::<Vec<_>>();
        assert_eq!(ips, vec![remote_b]);
    }

    #[test]
    fn best_endpoint_addr_for_local_prefers_ipv6_when_local_has_no_ipv4() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let local: SocketAddr = "[2001:db8::1]:7777".parse().unwrap();
        let remote_v4: SocketAddr = "192.0.2.1:7777".parse().unwrap();
        let remote_v6: SocketAddr = "[fd00::1]:7777".parse().unwrap();

        let local = EndpointAddr::from_parts(pk, [TransportAddr::Ip(local)]);
        let remote = EndpointAddr::from_parts(
            pk,
            [TransportAddr::Ip(remote_v4), TransportAddr::Ip(remote_v6)],
        );

        let best = best_endpoint_addr_for_local(&remote, &local);
        let ips = best.ip_addrs().copied().collect::<Vec<_>>();
        assert_eq!(ips, vec![remote_v6]);
    }

    #[test]
    fn best_endpoint_addr_for_local_prefers_ipv4_when_local_has_ipv4() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let local: SocketAddr = "198.51.100.10:7777".parse().unwrap();
        let remote_v4: SocketAddr = "192.0.2.1:7777".parse().unwrap();
        let remote_v6: SocketAddr = "[fd00::1]:7777".parse().unwrap();

        let local = EndpointAddr::from_parts(pk, [TransportAddr::Ip(local)]);
        let remote = EndpointAddr::from_parts(
            pk,
            [TransportAddr::Ip(remote_v4), TransportAddr::Ip(remote_v6)],
        );

        let best = best_endpoint_addr_for_local(&remote, &local);
        let ips = best.ip_addrs().copied().collect::<Vec<_>>();
        assert_eq!(ips, vec![remote_v4]);
    }

    #[test]
    fn best_endpoint_addr_for_local_skips_remote_local_only_addrs_when_possible() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let local: SocketAddr = "192.168.1.10:7777".parse().unwrap();
        let remote_local_only: SocketAddr = "169.254.1.10:7777".parse().unwrap();
        let remote_good: SocketAddr = "192.168.1.20:7777".parse().unwrap();

        let local = EndpointAddr::from_parts(pk, [TransportAddr::Ip(local)]);
        let remote = EndpointAddr::from_parts(
            pk,
            [
                TransportAddr::Ip(remote_local_only),
                TransportAddr::Ip(remote_good),
            ],
        );

        let best = best_endpoint_addr_for_local(&remote, &local);
        let ips = best.ip_addrs().copied().collect::<Vec<_>>();
        assert_eq!(ips, vec![remote_good]);
    }

    #[test]
    fn best_endpoint_addr_for_local_allows_loopback_when_local_is_loopback_only() {
        let mut rng = rand::rng();
        let sk = SecretKey::generate(&mut rng);
        let pk = sk.public();

        let local: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let remote_loopback: SocketAddr = "127.0.0.1:7778".parse().unwrap();

        let local = EndpointAddr::from_parts(pk, [TransportAddr::Ip(local)]);
        let remote = EndpointAddr::from_parts(pk, [TransportAddr::Ip(remote_loopback)]);

        let best = best_endpoint_addr_for_local(&remote, &local);
        let ips = best.ip_addrs().copied().collect::<Vec<_>>();
        assert_eq!(ips, vec![remote_loopback]);
    }
}
