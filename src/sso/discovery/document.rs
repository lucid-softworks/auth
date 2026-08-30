use super::{DiscoveryError, DiscoveryErrorCode, normalize_url};
use serde::{Deserialize, Serialize};

pub const REQUIRED_DISCOVERY_FIELDS: [&str; 4] = [
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub scopes_supported: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsoTokenEndpointAuthentication {
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcConfig {
    pub issuer: Option<String>,
    pub discovery_endpoint: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_endpoint: Option<String>,
    pub user_info_endpoint: Option<String>,
    pub token_endpoint_authentication: Option<SsoTokenEndpointAuthentication>,
    pub scopes_supported: Option<Vec<String>>,
}

pub fn validate_discovery_document(
    document: &OidcDiscoveryDocument,
    configured_issuer: &str,
) -> Result<(), DiscoveryError> {
    let fields = [
        ("issuer", document.issuer.as_deref()),
        (
            "authorization_endpoint",
            document.authorization_endpoint.as_deref(),
        ),
        ("token_endpoint", document.token_endpoint.as_deref()),
        ("jwks_uri", document.jwks_uri.as_deref()),
    ];
    let missing = fields
        .into_iter()
        .filter_map(|(name, value)| value.filter(|value| !value.is_empty()).is_none().then_some(name))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(DiscoveryError::new(
            DiscoveryErrorCode::Incomplete,
            format!(
                "Discovery document is missing required fields: {}",
                missing.join(", ")
            ),
        ));
    }
    let discovered = document.issuer.as_deref().expect("validated issuer");
    if discovered.trim_end_matches('/') != configured_issuer.trim_end_matches('/') {
        return Err(DiscoveryError::new(
            DiscoveryErrorCode::IssuerMismatch,
            format!(
                "Discovered issuer \"{discovered}\" does not match configured issuer \"{configured_issuer}\""
            ),
        ));
    }
    Ok(())
}

pub fn normalize_discovery_urls(
    document: &OidcDiscoveryDocument,
    issuer: &str,
    is_trusted_origin: impl Fn(&str) -> bool,
) -> Result<OidcDiscoveryDocument, DiscoveryError> {
    let mut output = document.clone();
    output.token_endpoint = normalize_required(
        "token_endpoint",
        output.token_endpoint.as_deref(),
        issuer,
        &is_trusted_origin,
    )?;
    output.authorization_endpoint = normalize_required(
        "authorization_endpoint",
        output.authorization_endpoint.as_deref(),
        issuer,
        &is_trusted_origin,
    )?;
    output.jwks_uri = normalize_required(
        "jwks_uri",
        output.jwks_uri.as_deref(),
        issuer,
        &is_trusted_origin,
    )?;
    for (name, endpoint) in [
        ("userinfo_endpoint", &mut output.userinfo_endpoint),
        ("revocation_endpoint", &mut output.revocation_endpoint),
        ("end_session_endpoint", &mut output.end_session_endpoint),
        ("introspection_endpoint", &mut output.introspection_endpoint),
    ] {
        if let Some(value) = endpoint.as_deref() {
            *endpoint = Some(normalize_trusted(name, value, issuer, &is_trusted_origin)?);
        }
    }
    Ok(output)
}

pub fn select_token_endpoint_auth_method(
    document: &OidcDiscoveryDocument,
    existing: Option<SsoTokenEndpointAuthentication>,
) -> SsoTokenEndpointAuthentication {
    if let Some(existing) = existing {
        return existing;
    }
    let supported = document
        .token_endpoint_auth_methods_supported
        .as_deref()
        .unwrap_or_default();
    for (name, method) in [
        (
            "client_secret_basic",
            SsoTokenEndpointAuthentication::ClientSecretBasic,
        ),
        (
            "client_secret_post",
            SsoTokenEndpointAuthentication::ClientSecretPost,
        ),
        (
            "private_key_jwt",
            SsoTokenEndpointAuthentication::PrivateKeyJwt,
        ),
    ] {
        if supported.contains(&name.to_owned()) {
            return method;
        }
    }
    SsoTokenEndpointAuthentication::ClientSecretBasic
}

pub fn needs_runtime_discovery(config: Option<&OidcConfig>) -> bool {
    config.is_none_or(|config| {
        config.token_endpoint.is_none()
            || config.jwks_endpoint.is_none()
            || config.authorization_endpoint.is_none()
    })
}

fn normalize_required(
    name: &str,
    endpoint: Option<&str>,
    issuer: &str,
    is_trusted_origin: &impl Fn(&str) -> bool,
) -> Result<Option<String>, DiscoveryError> {
    endpoint
        .map(|value| normalize_trusted(name, value, issuer, is_trusted_origin))
        .transpose()
}

fn normalize_trusted(
    name: &str,
    endpoint: &str,
    issuer: &str,
    is_trusted_origin: &impl Fn(&str) -> bool,
) -> Result<String, DiscoveryError> {
    let url = normalize_url(name, endpoint, issuer)?;
    if !is_trusted_origin(&url) {
        return Err(DiscoveryError::new(
            DiscoveryErrorCode::UntrustedOrigin,
            format!(
                "The {name} \"{url}\" is not trusted by your trusted origins configuration."
            ),
        ));
    }
    Ok(url)
}
