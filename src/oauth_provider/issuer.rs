use std::net::IpAddr;

/// Better Auth's semantic issuer normalization. Endpoint URLs continue to use
/// the configured/request base URL; only protocol `iss`/issuer values use this.
pub(crate) fn normalize_issuer(value: &str) -> String {
    let Ok(mut issuer) = url::Url::parse(value) else {
        return value.to_owned();
    };
    if issuer.scheme() != "https" && !loopback_host(issuer.host_str().unwrap_or_default()) {
        let _ = issuer.set_scheme("https");
    }
    issuer.set_query(None);
    issuer.set_fragment(None);
    issuer
        .as_str()
        .strip_suffix('/')
        .unwrap_or(issuer.as_str())
        .to_owned()
}

fn loopback_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_pinned_issuer_sanitizer() {
        assert_eq!(
            normalize_issuer("http://issuer.example/path/?query=yes#fragment"),
            "https://issuer.example/path"
        );
        assert_eq!(
            normalize_issuer("http://localhost:3000/api/auth/"),
            "http://localhost:3000/api/auth"
        );
        assert_eq!(normalize_issuer("not a url"), "not a url");
    }
}
