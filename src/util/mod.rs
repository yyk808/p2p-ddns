use std::net::{IpAddr, SocketAddr};

use anyhow::Result;
use iroh::EndpointAddr;

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
}
