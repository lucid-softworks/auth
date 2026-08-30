use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) fn is_public_routable_host(host: &str) -> bool {
    let host = host.trim();
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split_once(']').map_or(bracketed, |(host, _)| host)
    } else if host.bytes().filter(|byte| *byte == b':').count() == 1 {
        host.split_once(':').map_or(host, |(host, _)| host)
    } else {
        host
    };
    let lowercase = host
        .split_once('%')
        .map_or(host, |(host, _)| host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if lowercase.is_empty()
        || matches!(
            lowercase.as_str(),
            "localhost"
                | "metadata.google.internal"
                | "metadata.goog"
                | "metadata"
                | "instance-data"
                | "instance-data.ec2.internal"
        )
        || lowercase.ends_with(".localhost")
    {
        return false;
    }
    lowercase.parse::<IpAddr>().map_or(true, public_routable_ip)
}

pub(crate) fn public_routable_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => public_routable_ipv4(address),
        IpAddr::V6(address) => public_routable_ipv6(address),
    }
}

fn public_routable_ipv4(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    ![
        ("0.0.0.0", 8),
        ("10.0.0.0", 8),
        ("100.64.0.0", 10),
        ("127.0.0.0", 8),
        ("169.254.0.0", 16),
        ("172.16.0.0", 12),
        ("192.0.0.0", 24),
        ("192.0.2.0", 24),
        ("192.88.99.0", 24),
        ("192.168.0.0", 16),
        ("198.18.0.0", 15),
        ("198.51.100.0", 24),
        ("203.0.113.0", 24),
        ("224.0.0.0", 4),
        ("240.0.0.0", 4),
    ]
    .into_iter()
    .any(|(prefix, length)| in_ipv4_range(value, prefix, length))
}

fn in_ipv4_range(value: u32, prefix: &str, length: u32) -> bool {
    let prefix = prefix.parse::<Ipv4Addr>().expect("static IPv4 prefix");
    let mask = u32::MAX << (32_u32 - length);
    value & mask == u32::from(prefix) & mask
}

fn public_routable_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return public_routable_ipv4(mapped);
    }
    let value = u128::from(address);
    let in_range = |prefix: &str, length: u32| {
        let prefix = prefix.parse::<Ipv6Addr>().expect("static IPv6 prefix");
        let mask = u128::MAX << (128_u32 - length);
        value & mask == u128::from(prefix) & mask
    };
    if [
        ("::", 96),
        ("64:ff9b::", 96),
        ("64:ff9b:1::", 48),
        ("100::", 64),
        ("2001::", 32),
        ("2001:2::", 48),
        ("2001:db8::", 32),
        ("3fff::", 20),
        ("5f00::", 16),
        ("fc00::", 7),
        ("fe80::", 10),
        ("fec0::", 10),
        ("ff00::", 8),
    ]
    .into_iter()
    .any(|(prefix, length)| in_range(prefix, length))
    {
        return false;
    }
    if in_range("2002::", 16) {
        let segments = address.segments();
        return public_routable_ipv4(Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            segments[1] as u8,
            (segments[2] >> 8) as u8,
            segments[2] as u8,
        ));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_rfc_6890_and_cloud_metadata_targets() {
        for host in [
            "localhost",
            "tenant.localhost.",
            "metadata.google.internal.",
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "64:ff9b::7f00:1",
        ] {
            assert!(!is_public_routable_host(host), "{host}");
        }
        for host in ["example.com", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_routable_host(host), "{host}");
        }
    }
}
