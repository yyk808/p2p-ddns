use std::net::{IpAddr, SocketAddr};

use anyhow::Result;
use iroh::{EndpointAddr, TransportAddr};

pub fn time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn parse_bind_addr(bind: &str) -> Result<SocketAddr> {
    Ok(bind.parse::<SocketAddr>()?)
}

pub fn best_ip_for_display(addr: &EndpointAddr) -> Option<IpAddr> {
    let mut best_v6: Option<IpAddr> = None;
    for sock in addr.ip_addrs() {
        let ip = sock.ip();
        if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
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
    let local_ips: Vec<IpAddr> = local.ip_addrs().map(|sock| sock.ip()).collect();
    if local_ips.is_empty() {
        return remote.clone();
    }

    let mut best: Option<(u32, bool, SocketAddr)> = None;
    for sock in remote.ip_addrs() {
        let score = best_prefix_score(sock.ip(), &local_ips);
        let is_v4 = sock.ip().is_ipv4();
        let candidate = (score, is_v4, *sock);
        if let Some(current) = best {
            if candidate.0 > current.0 || (candidate.0 == current.0 && candidate.1 && !current.1) {
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
}
