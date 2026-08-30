use crate::{
    AuthService,
    sso::{
        DiscoveryError, DiscoveryErrorCode, SsoTokenEndpointAuthentication,
        compute_discovery_url, fetch_discovery_document, normalize_discovery_urls,
        select_token_endpoint_auth_method, validate_discovery_document,
        validate_oidc_endpoint_url,
    },
};
use axum::{http::StatusCode, response::Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RegistrationConfig {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_info_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_authentication: Option<SsoTokenEndpointAuthentication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discovery_endpoint: Option<String>,
    #[serde(default)]
    skip_discovery: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<String>>,
    #[serde(default = "default_pkce")]
    pkce: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mapping: Option<Value>,
}

const fn default_pkce() -> bool {
    true
}

pub(super) async fn prepare(
    service: &AuthService,
    issuer: &str,
    override_user_info: bool,
    config: &RegistrationConfig,
) -> Result<Value, Box<Response>> {
    validate_endpoints(service, config)?;
    let mut persisted = serde_json::to_value(config)
        .expect("OIDC registration config is JSON")
        .as_object()
        .cloned()
        .expect("OIDC registration config is an object");
    persisted.remove("skipDiscovery");
    persisted.insert("issuer".into(), json!(issuer));
    persisted.insert("overrideUserInfo".into(), json!(override_user_info));
    if config.skip_discovery {
        persisted
            .entry("discoveryEndpoint")
            .or_insert_with(|| json!(compute_discovery_url(issuer)));
        persisted
            .entry("tokenEndpointAuthentication")
            .or_insert_with(|| json!("client_secret_basic"));
    } else {
        hydrate(service, issuer, config, &mut persisted).await?;
    }
    validate_authentication(config, &persisted)?;
    Ok(Value::Object(persisted))
}

fn validate_endpoints(
    service: &AuthService,
    config: &RegistrationConfig,
) -> Result<(), Box<Response>> {
    for (name, endpoint) in [
        ("authorizationEndpoint", config.authorization_endpoint.as_deref()),
        ("tokenEndpoint", config.token_endpoint.as_deref()),
        ("userInfoEndpoint", config.user_info_endpoint.as_deref()),
        ("jwksEndpoint", config.jwks_endpoint.as_deref()),
        ("discoveryEndpoint", config.discovery_endpoint.as_deref()),
    ] {
        if let Some(endpoint) = endpoint {
            validate_oidc_endpoint_url(name, endpoint, |url| service.trusts_origin(url))
                .map_err(|error| Box::new(discovery_error(error)))?;
        }
    }
    Ok(())
}

async fn hydrate(
    service: &AuthService,
    issuer: &str,
    config: &RegistrationConfig,
    persisted: &mut serde_json::Map<String, Value>,
) -> Result<(), Box<Response>> {
    let endpoint = config
        .discovery_endpoint
        .clone()
        .unwrap_or_else(|| compute_discovery_url(issuer));
    let document = fetch_discovery_document(&endpoint, 10_000, |url| service.trusts_origin(url))
        .await
        .map_err(|error| Box::new(discovery_error(error)))?;
    validate_discovery_document(&document, issuer)
        .map_err(|error| Box::new(discovery_error(error)))?;
    let document = normalize_discovery_urls(&document, issuer, |url| service.trusts_origin(url))
        .map_err(|error| Box::new(discovery_error(error)))?;
    for (name, explicit, discovered) in [
        (
            "authorizationEndpoint",
            config.authorization_endpoint.as_ref(),
            document.authorization_endpoint.as_ref(),
        ),
        (
            "tokenEndpoint",
            config.token_endpoint.as_ref(),
            document.token_endpoint.as_ref(),
        ),
        (
            "jwksEndpoint",
            config.jwks_endpoint.as_ref(),
            document.jwks_uri.as_ref(),
        ),
        (
            "userInfoEndpoint",
            config.user_info_endpoint.as_ref(),
            document.userinfo_endpoint.as_ref(),
        ),
    ] {
        if let Some(value) = explicit.or(discovered) {
            persisted.insert(name.into(), json!(value));
        }
    }
    persisted.insert("discoveryEndpoint".into(), json!(endpoint));
    persisted.insert(
        "tokenEndpointAuthentication".into(),
        json!(select_token_endpoint_auth_method(
            &document,
            config.token_endpoint_authentication,
        )),
    );
    Ok(())
}

fn validate_authentication(
    config: &RegistrationConfig,
    persisted: &serde_json::Map<String, Value>,
) -> Result<(), Box<Response>> {
    let private_key = persisted
        .get("tokenEndpointAuthentication")
        .and_then(Value::as_str)
        == Some("private_key_jwt");
    if private_key {
        return Err(Box::new(super::super::support::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "private_key_jwt authentication requires either a resolvePrivateKey callback or a privateKey in defaultSSO",
        )));
    }
    if config.client_secret.as_deref().is_none_or(str::is_empty) {
        return Err(Box::new(super::super::support::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "clientSecret is required when using client_secret_basic or client_secret_post authentication",
        )));
    }
    Ok(())
}

fn discovery_error(error: DiscoveryError) -> Response {
    use DiscoveryErrorCode::{Timeout, Unexpected};
    let (status, message) = match error.code {
        Timeout => (
            StatusCode::BAD_GATEWAY,
            format!("OIDC discovery timed out: {}", error.message),
        ),
        Unexpected => (
            StatusCode::BAD_GATEWAY,
            format!("OIDC discovery failed: {}", error.message),
        ),
        _ => (StatusCode::BAD_REQUEST, error.message),
    };
    crate::axum::api_error(status, error.code.as_str(), message)
}
