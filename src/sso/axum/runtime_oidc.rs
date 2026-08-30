use crate::{
    AuthService,
    sso::{
        DiscoveryError, DiscoveryErrorCode, OidcConfig, compute_discovery_url,
        fetch_discovery_document, needs_runtime_discovery, normalize_discovery_urls,
        select_token_endpoint_auth_method, validate_discovery_document,
        validate_oidc_endpoint_egress,
    },
};
use axum::{http::StatusCode, response::Response};
use serde_json::{Map, Value, json};

pub(super) async fn ensure(
    service: &AuthService,
    issuer: &str,
    config: &Map<String, Value>,
) -> Result<Map<String, Value>, DiscoveryError> {
    let parsed = serde_json::from_value::<OidcConfig>(Value::Object(config.clone())).ok();
    if !needs_runtime_discovery(parsed.as_ref()) {
        validate_runtime_endpoints(service, config).await?;
        return Ok(config.clone());
    }
    let endpoint = config
        .get("discoveryEndpoint")
        .and_then(Value::as_str)
        .filter(|endpoint| !endpoint.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| compute_discovery_url(issuer));
    let document = fetch_discovery_document(&endpoint, 10_000, |url| service.trusts_origin(url))
        .await
        ?;
    validate_discovery_document(&document, issuer)?;
    let document = normalize_discovery_urls(&document, issuer, |url| service.trusts_origin(url))
        ?;
    let mut hydrated = config.clone();
    for (field, discovered) in [
        ("authorizationEndpoint", document.authorization_endpoint.clone()),
        ("tokenEndpoint", document.token_endpoint.clone()),
        ("jwksEndpoint", document.jwks_uri.clone()),
        ("userInfoEndpoint", document.userinfo_endpoint.clone()),
    ] {
        if !hydrated
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
            && let Some(discovered) = discovered
        {
            hydrated.insert(field.into(), json!(discovered));
        }
    }
    hydrated.insert("discoveryEndpoint".into(), json!(endpoint));
    if !hydrated.contains_key("tokenEndpointAuthentication") {
        hydrated.insert(
            "tokenEndpointAuthentication".into(),
            json!(select_token_endpoint_auth_method(
                &document,
                parsed.and_then(|config| config.token_endpoint_authentication),
            )),
        );
    }
    validate_runtime_endpoints(service, &hydrated).await?;
    Ok(hydrated)
}

async fn validate_runtime_endpoints(
    service: &AuthService,
    config: &Map<String, Value>,
) -> Result<(), DiscoveryError> {
    for (name, endpoint) in [
        ("tokenEndpoint", config.get("tokenEndpoint")),
        ("jwksEndpoint", config.get("jwksEndpoint")),
        ("userInfoEndpoint", config.get("userInfoEndpoint")),
    ] {
        if let Some(endpoint) = endpoint.and_then(Value::as_str) {
            validate_oidc_endpoint_egress(name, endpoint, |url| service.trusts_origin(url)).await?;
        }
    }
    Ok(())
}

pub(super) fn api_error(error: DiscoveryError) -> Response {
    use DiscoveryErrorCode::{
        EndpointRedirect, Incomplete, InvalidJson, InvalidUrl, IssuerMismatch, NotFound,
        PrivateHost, Timeout, Unexpected, UntrustedOrigin,
    };
    let (status, message) = match error.code {
        Timeout => (
            StatusCode::BAD_GATEWAY,
            format!("OIDC discovery timed out: {}", error.message),
        ),
        Unexpected => (
            StatusCode::BAD_GATEWAY,
            format!("OIDC discovery failed: {}", error.message),
        ),
        EndpointRedirect | InvalidJson | InvalidUrl | NotFound | PrivateHost | UntrustedOrigin => {
            (StatusCode::BAD_REQUEST, error.message)
        }
        Incomplete => (
            StatusCode::BAD_REQUEST,
            format!("Incomplete OIDC discovery: {}", error.message),
        ),
        IssuerMismatch => (
            StatusCode::BAD_REQUEST,
            format!("OIDC issuer mismatch: {}", error.message),
        ),
    };
    crate::axum::api_error(status, error.code.as_str(), message)
}
