use super::input::ClientMetadataInput;
use crate::oauth_provider::{OAuthProviderConfig, OAuthProviderError};
use std::net::{IpAddr, Ipv6Addr};
use url::Url;

pub(super) fn validate(
    config: &OAuthProviderConfig,
    input: &ClientMetadataInput,
) -> Result<(), OAuthProviderError> {
    if let Some(redirects) = &input.post_logout_redirect_uris {
        if redirects.is_empty() {
            return invalid("post_logout_redirect_uris must contain at least one URL");
        }
        for redirect in redirects {
            validate_safe_url(redirect)?;
        }
    }
    if let Some(uri) = input.backchannel_logout_uri.as_deref() {
        validate_backchannel(config, uri)?;
    }
    Ok(())
}

fn validate_safe_url(value: &str) -> Result<(), OAuthProviderError> {
    let url = Url::parse(value)
        .map_err(|_| OAuthProviderError::InvalidRequest("URL must be parseable".into()))?;
    if matches!(url.scheme(), "javascript" | "data" | "vbscript") {
        return invalid("URL cannot use javascript:, data:, or vbscript: scheme");
    }
    if value.contains('#') {
        return invalid("Redirect URI must not contain a fragment component");
    }
    if url.scheme() == "http" && !loopback_host(url.host_str().unwrap_or_default()) {
        return invalid("Redirect URI must use HTTPS (HTTP allowed only for loopback hosts)");
    }
    Ok(())
}

fn validate_backchannel(
    config: &OAuthProviderConfig,
    value: &str,
) -> Result<(), OAuthProviderError> {
    if config.disable_jwt_plugin {
        return invalid(
            "backchannel_logout_uri requires the jwt plugin (disableJwtPlugin must be false)",
        );
    }
    let url = Url::parse(value).map_err(|_| {
        OAuthProviderError::InvalidRequest("backchannel_logout_uri must be an absolute URL".into())
    })?;
    if value.contains('#') {
        return invalid("backchannel_logout_uri must not include a fragment component");
    }
    if url.scheme() != "https" {
        return invalid("backchannel_logout_uri must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return invalid("backchannel_logout_uri must not contain credentials");
    }
    if url.host_str().is_none_or(private_or_reserved_host) {
        return invalid("backchannel_logout_uri must not point to a private or reserved address");
    }
    Ok(())
}

fn loopback_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn private_or_reserved_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if matches!(
        host.as_str(),
        "localhost"
            | "metadata"
            | "metadata.goog"
            | "metadata.google.internal"
            | "instance-data"
            | "instance-data.ec2.internal"
    ) || host.ends_with(".localhost")
    {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(private_or_reserved_ip)
}

fn private_or_reserved_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, ..] = address.octets();
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
                || first == 0
                || first >= 240
                || (first == 100 && (64..=127).contains(&second))
                || (first == 192 && second == 0)
                || (first == 192 && second == 88)
                || (first == 198 && matches!(second, 18 | 19))
        }
        IpAddr::V6(address) => private_or_reserved_ipv6(address),
    }
}

fn private_or_reserved_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return private_or_reserved_ip(mapped.into());
    }
    let segments = address.segments();
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || segments[0] & 0xffc0 == 0xfec0
        || segments[..2] == [0x2001, 0x0db8]
        || segments[..3] == [0x2001, 0x0002, 0x0000]
        || segments[..2] == [0x0064, 0xff9b]
        || segments[..2] == [0x2001, 0x0000]
        || segments[0] == 0x0100
        || segments[0] == 0x5f00
        || segments[0] == 0x3fff
        || segments[..6] == [0, 0, 0, 0, 0, 0]
        || tunneled_private_ipv4(segments)
}

fn tunneled_private_ipv4(segments: [u16; 8]) -> bool {
    if segments[0] != 0x2002 {
        return false;
    }
    let address = std::net::Ipv4Addr::new(
        (segments[1] >> 8) as u8,
        segments[1] as u8,
        (segments[2] >> 8) as u8,
        segments[2] as u8,
    );
    private_or_reserved_ip(address.into())
}

fn invalid<T>(message: &str) -> Result<T, OAuthProviderError> {
    Err(OAuthProviderError::InvalidRequest(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_backchannel_targets_and_disabled_jwt() {
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        for uri in [
            "http://example.com/logout",
            "https://127.0.0.1/logout",
            "https://169.254.169.254/logout",
            "https://metadata.google.internal/logout",
            "https://user@example.com/logout",
            "https://example.com/logout#fragment",
        ] {
            assert!(validate_backchannel(&config, uri).is_err(), "{uri}");
        }
        assert!(validate_backchannel(&config, "https://rp.example/logout").is_ok());
        config.disable_jwt_plugin = true;
        assert!(validate_backchannel(&config, "https://rp.example/logout").is_err());
    }

    #[test]
    fn post_logout_redirects_use_the_pinned_safe_url_policy() {
        for uri in [
            "https://rp.example/logout",
            "http://localhost/logout",
            "com.example.app:/logout",
        ] {
            assert!(validate_safe_url(uri).is_ok(), "{uri}");
        }
        for uri in [
            "http://rp.example/logout",
            "javascript:alert(1)",
            "https://rp.example/logout#fragment",
        ] {
            assert!(validate_safe_url(uri).is_err(), "{uri}");
        }
    }
}
