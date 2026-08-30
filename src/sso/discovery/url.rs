use super::{DiscoveryError, DiscoveryErrorCode};
use url::Url;

pub fn compute_discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.strip_suffix('/').unwrap_or(issuer)
    )
}

pub fn validate_discovery_url(
    endpoint: &str,
    is_trusted_origin: impl Fn(&str) -> bool,
) -> Result<String, DiscoveryError> {
    let endpoint = parse_url("discoveryEndpoint", endpoint, None)?.to_string();
    if !is_trusted_origin(&endpoint) {
        return Err(DiscoveryError::new(
            DiscoveryErrorCode::UntrustedOrigin,
            format!(
                "The main discovery endpoint \"{endpoint}\" is not trusted by your trusted origins configuration."
            ),
        ));
    }
    Ok(endpoint)
}

pub fn validate_oidc_endpoint_url(
    name: &str,
    endpoint: &str,
    is_trusted_origin: impl Fn(&str) -> bool,
) -> Result<String, DiscoveryError> {
    let parsed = parse_url(name, endpoint, None)?;
    let normalized = parsed.to_string();
    let host = parsed.host_str().unwrap_or_default();
    if crate::network_address::is_public_routable_host(host) || is_trusted_origin(&normalized) {
        return Ok(normalized);
    }
    Err(DiscoveryError::new(
        DiscoveryErrorCode::PrivateHost,
        format!(
            "The {name} URL ({normalized}) is not publicly routable: {host}. If this is an internal IdP, add its origin to trustedOrigins."
        ),
    ))
}

pub fn normalize_url(name: &str, endpoint: &str, issuer: &str) -> Result<String, DiscoveryError> {
    if let Ok(url) = parse_url(name, endpoint, None) {
        return Ok(url.to_string());
    }
    let issuer_url = parse_url(name, issuer, None)?;
    let base_path = issuer_url.path().trim_end_matches('/');
    let endpoint_path = endpoint.trim_start_matches('/');
    parse_url(
        name,
        &format!("{base_path}/{endpoint_path}"),
        Some(&issuer_url),
    )
    .map(|url| url.to_string())
}

fn parse_url(name: &str, endpoint: &str, base: Option<&Url>) -> Result<Url, DiscoveryError> {
    let parsed = match base {
        Some(base) => base.join(endpoint),
        None => Url::parse(endpoint),
    }
    .map_err(|_| {
        DiscoveryError::new(
            DiscoveryErrorCode::InvalidUrl,
            format!("The url \"{name}\" must be valid: {endpoint}"),
        )
    })?;
    if matches!(parsed.scheme(), "http" | "https") {
        return Ok(parsed);
    }
    Err(DiscoveryError::new(
        DiscoveryErrorCode::InvalidUrl,
        format!(
            "The url \"{name}\" must use the http or https supported protocols: {endpoint}"
        ),
    ))
}
