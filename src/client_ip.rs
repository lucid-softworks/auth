use crate::AuthError;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv6Addr};

/// Better Auth-compatible IP tracking and forwarding configuration.
#[derive(Debug, Clone)]
pub struct IpAddressConfig {
    /// Header names checked in order. Better Auth defaults to
    /// `x-forwarded-for`.
    pub ip_address_headers: Vec<String>,
    /// Disables session IP metadata and IP-based throttling.
    pub disable_ip_tracking: bool,
    /// IPv6 prefix length used for rate-limit and session IP normalization.
    pub ipv6_subnet: u8,
    trusted_proxies: Vec<IpNet>,
}

impl Default for IpAddressConfig {
    fn default() -> Self {
        Self {
            ip_address_headers: vec!["x-forwarded-for".into()],
            disable_ip_tracking: false,
            ipv6_subnet: 64,
            trusted_proxies: Vec::new(),
        }
    }
}

impl IpAddressConfig {
    /// Adds an exact proxy address or CIDR range allowed to supply forwarding
    /// headers.
    pub fn trust_proxy(&mut self, address_or_cidr: &str) -> Result<(), AuthError> {
        let network = address_or_cidr
            .parse::<IpNet>()
            .ok()
            .or_else(|| address_or_cidr.parse::<IpAddr>().ok().map(IpNet::from))
            .ok_or_else(|| {
                AuthError::InvalidConfiguration(format!(
                    "trusted proxy `{address_or_cidr}` must be an IP address or CIDR range"
                ))
            })?;
        self.trusted_proxies.push(network);
        Ok(())
    }

    pub fn trusted_proxies(&self) -> impl Iterator<Item = String> + '_ {
        self.trusted_proxies.iter().map(ToString::to_string)
    }

    /// Resolves a normalized client IP from a verified transport peer and the
    /// configured forwarding headers.
    pub fn resolve_client_ip<F>(&self, peer: IpAddr, mut header: F) -> Option<String>
    where
        F: FnMut(&str) -> Option<String>,
    {
        if self.disable_ip_tracking {
            return None;
        }
        let peer = canonical_ip(peer);
        if !self.is_trusted_proxy(peer) {
            return Some(normalize_ip(peer, self.ipv6_subnet));
        }

        for name in &self.ip_address_headers {
            if let Some(value) = header(name)
                && let Some(client) = self.resolve_forwarded_chain(&value)
            {
                return Some(normalize_ip(client, self.ipv6_subnet));
            }
        }
        // A trusted edge without a usable forwarding header becomes a shared
        // bucket instead of silently disabling IP throttling.
        Some(normalize_ip(peer, self.ipv6_subnet))
    }

    fn resolve_forwarded_chain(&self, value: &str) -> Option<IpAddr> {
        for hop in value.split(',').rev() {
            let hop = canonical_ip(hop.trim().parse().ok()?);
            if !self.is_trusted_proxy(hop) {
                return Some(hop);
            }
        }
        None
    }

    fn is_trusted_proxy(&self, address: IpAddr) -> bool {
        self.trusted_proxies
            .iter()
            .any(|network| network.contains(&address))
    }
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn normalize_ip(address: IpAddr, ipv6_subnet: u8) -> String {
    match address {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => {
            let prefix = u32::from(ipv6_subnet);
            let value = if prefix < 128 {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(address) & mask
            } else {
                u128::from(address)
            };
            expanded_ipv6(Ipv6Addr::from(value))
        }
    }
}

fn expanded_ipv6(address: Ipv6Addr) -> String {
    address
        .segments()
        .map(|segment| format!("{segment:04x}"))
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn resolve(config: &IpAddressConfig, peer: &str, headers: &[(&str, &str)]) -> Option<String> {
        let headers = headers.iter().copied().collect::<HashMap<_, _>>();
        config.resolve_client_ip(peer.parse().unwrap(), |name| {
            headers.get(name).map(ToString::to_string)
        })
    }

    #[test]
    fn direct_clients_cannot_spoof_forwarding_headers() {
        let config = IpAddressConfig::default();
        for peer in ["198.51.100.9", "192.168.1.4"] {
            assert_eq!(
                resolve(&config, peer, &[("x-forwarded-for", "203.0.113.10")]).as_deref(),
                Some(peer)
            );
        }
    }

    #[test]
    fn walks_trusted_ipv4_and_ipv6_proxy_chains_from_the_edge() {
        let mut config = IpAddressConfig::default();
        config.trust_proxy("10.0.0.0/8").unwrap();
        config.trust_proxy("2001:db8:1::/48").unwrap();
        assert_eq!(
            resolve(
                &config,
                "10.0.0.3",
                &[("x-forwarded-for", "198.51.100.7, 10.0.0.2")]
            )
            .as_deref(),
            Some("198.51.100.7")
        );
        assert_eq!(
            resolve(
                &config,
                "2001:db8:1::3",
                &[("x-forwarded-for", "2001:db8:abcd::1234, 2001:db8:1::2")]
            )
            .as_deref(),
            Some("2001:0db8:abcd:0000:0000:0000:0000:0000")
        );
    }

    #[test]
    fn rejects_malformed_chains_and_normalizes_mapped_ipv4() {
        let mut config = IpAddressConfig::default();
        config.trust_proxy("10.0.0.0/8").unwrap();
        assert_eq!(
            resolve(
                &config,
                "10.0.0.3",
                &[("x-forwarded-for", "198.51.100.7, not-an-ip")]
            )
            .as_deref(),
            Some("10.0.0.3")
        );
        assert_eq!(
            resolve(&config, "::ffff:192.0.2.9", &[]).as_deref(),
            Some("192.0.2.9")
        );
    }

    #[test]
    fn supports_custom_headers_and_disable_tracking() {
        let mut config = IpAddressConfig {
            ip_address_headers: vec!["cf-connecting-ip".into()],
            ..IpAddressConfig::default()
        };
        config.trust_proxy("192.0.2.0/24").unwrap();
        config.trust_proxy("2001:db8::10").unwrap();
        assert!(config.trust_proxy("not-a-network").is_err());
        assert_eq!(
            resolve(&config, "192.0.2.4", &[("cf-connecting-ip", "203.0.113.8")]).as_deref(),
            Some("203.0.113.8")
        );
        config.disable_ip_tracking = true;
        assert_eq!(resolve(&config, "192.0.2.4", &[]), None);
    }
}
