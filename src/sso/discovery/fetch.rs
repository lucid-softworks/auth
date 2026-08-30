use super::{
    DiscoveryError, DiscoveryErrorCode, OidcDiscoveryDocument, validate_oidc_endpoint_url,
};
use std::{net::IpAddr, time::Duration};
use url::Url;

pub async fn fetch_discovery_document(
    endpoint: &str,
    timeout_ms: u64,
    is_trusted_origin: impl Fn(&str) -> bool + Sync,
) -> Result<OidcDiscoveryDocument, DiscoveryError> {
    let normalized = validate_oidc_endpoint_egress(
        "discoveryEndpoint",
        endpoint,
        &is_trusted_origin,
    )
    .await?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .map_err(|error| unexpected(endpoint, error))?;
    let response = client.get(&normalized).send().await.map_err(|error| {
        if error.is_timeout() {
            DiscoveryError::new(
                DiscoveryErrorCode::Timeout,
                "Discovery request timed out",
            )
        } else {
            unexpected(endpoint, error)
        }
    })?;
    let status = response.status();
    if status.is_redirection() {
        return Err(DiscoveryError::new(
            DiscoveryErrorCode::EndpointRedirect,
            format!(
                "The discoveryEndpoint ({endpoint}) returned an HTTP {} redirect. Configure the final OIDC endpoint URL instead of a redirecting URL.",
                status.as_u16()
            ),
        ));
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(DiscoveryError::new(
            DiscoveryErrorCode::NotFound,
            "Discovery endpoint not found",
        ));
    }
    if status == reqwest::StatusCode::REQUEST_TIMEOUT {
        return Err(DiscoveryError::new(
            DiscoveryErrorCode::Timeout,
            "Discovery request timed out",
        ));
    }
    if !status.is_success() {
        return Err(DiscoveryError::new(
            DiscoveryErrorCode::Unexpected,
            format!(
                "Unexpected discovery error: {}",
                status.canonical_reason().unwrap_or("Unknown error")
            ),
        ));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| unexpected(endpoint, error))?;
    if body.is_empty() {
        return Err(DiscoveryError::new(
            DiscoveryErrorCode::InvalidJson,
            "Discovery endpoint returned an empty response",
        ));
    }
    serde_json::from_slice(&body).map_err(|_| {
        DiscoveryError::new(
            DiscoveryErrorCode::InvalidJson,
            "Discovery endpoint returned invalid JSON",
        )
    })
}

pub async fn validate_oidc_endpoint_egress(
    name: &str,
    endpoint: &str,
    is_trusted_origin: impl Fn(&str) -> bool + Sync,
) -> Result<String, DiscoveryError> {
    let normalized = validate_oidc_endpoint_url(name, endpoint, &is_trusted_origin)?;
    if is_trusted_origin(&normalized) {
        return Ok(normalized);
    }
    let parsed = Url::parse(&normalized).expect("validated OIDC endpoint");
    let Some(host) = parsed.host_str() else {
        return Ok(normalized);
    };
    if host.parse::<IpAddr>().is_ok() {
        return Ok(normalized);
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    let Ok(addresses) = tokio::net::lookup_host((host, port)).await else {
        return Ok(normalized);
    };
    for address in addresses {
        if !crate::network_address::public_routable_ip(address.ip()) {
            return Err(DiscoveryError::new(
                DiscoveryErrorCode::PrivateHost,
                format!(
                    "The {name} host \"{host}\" resolves to a non-publicly-routable address ({}). If this is an internal IdP, add its origin to trustedOrigins.",
                    address.ip()
                ),
            ));
        }
    }
    Ok(normalized)
}

fn unexpected(endpoint: &str, error: impl std::fmt::Display) -> DiscoveryError {
    DiscoveryError::new(
        DiscoveryErrorCode::Unexpected,
        format!("Unexpected error during discovery: {error} ({endpoint})"),
    )
}
