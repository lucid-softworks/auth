use super::{input::ClientMetadataInput, registration::RegistrationSource, split_scopes};
use crate::{
    AuthService,
    oauth_provider::{OAuthCallbackContext, OAuthProviderConfig, OAuthProviderError},
};
use std::{collections::BTreeSet, net::IpAddr};
use url::Url;

pub(super) async fn validate_metadata(
    service: &AuthService,
    config: &OAuthProviderConfig,
    input: &ClientMetadataInput,
    source: RegistrationSource,
    context: &OAuthCallbackContext,
) -> Result<(), OAuthProviderError> {
    super::validation_support::validate_shape(input)?;
    validate_auth_method(config, input)?;
    validate_grants(config, input)?;
    validate_code_flow(input)?;
    validate_application(input)?;
    validate_subject(config, input)?;
    super::logout_validation::validate(config, input)?;
    super::key_material::validate(service, input)?;
    validate_scopes(config, input, source)?;
    let metadata = serde_json::to_value(input).unwrap_or_default();
    for extension in &config.extensions {
        extension
            .validate_client_metadata(&metadata, context)
            .await
            .map_err(|error| OAuthProviderError::InvalidClient(error.to_string()))?;
    }
    Ok(())
}

fn validate_auth_method(
    config: &OAuthProviderConfig,
    input: &ClientMetadataInput,
) -> Result<(), OAuthProviderError> {
    let auth_method = input
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic");
    let built_in = [
        "none",
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
    ]
    .contains(&auth_method);
    let extension = config.extensions.iter().any(|extension| {
        extension
            .client_authentication_methods()
            .iter()
            .any(|method| method.method == auth_method)
    });
    if built_in || extension {
        return Ok(());
    }
    Err(OAuthProviderError::InvalidRequest(format!(
        "unsupported token_endpoint_auth_method {auth_method}"
    )))
}

fn validate_grants(
    config: &OAuthProviderConfig,
    input: &ClientMetadataInput,
) -> Result<(), OAuthProviderError> {
    for grant in input.grant_types.iter().flatten() {
        let extension = config.extensions.iter().any(|extension| {
            extension
                .grant_types()
                .iter()
                .any(|supported| supported == grant)
        });
        if !config.grant_types.contains(grant) && !extension {
            return Err(OAuthProviderError::InvalidRequest(format!(
                "unsupported grant_type {grant}"
            )));
        }
    }
    Ok(())
}

fn validate_code_flow(input: &ClientMetadataInput) -> Result<(), OAuthProviderError> {
    let grants = input.grant_types.as_deref().unwrap_or(&[]);
    let response_types = input.response_types.as_deref().unwrap_or(&[]);
    let authorization_code = grants.iter().any(|grant| grant == "authorization_code");
    if authorization_code && !response_types.iter().any(|value| value == "code") {
        return Err(OAuthProviderError::InvalidRequest(
            "When 'authorization_code' grant type is used, 'code' response type must be included"
                .into(),
        ));
    }
    if !authorization_code && response_types.iter().any(|value| value == "code") {
        return Err(OAuthProviderError::InvalidRequest(
            "When 'code' response type is used, 'authorization_code' grant type must be included"
                .into(),
        ));
    }
    if authorization_code && input.redirect_uris.as_ref().is_none_or(Vec::is_empty) {
        return Err(OAuthProviderError::InvalidRedirectUri(
            "Redirect URIs are required for authorization_code and implicit grant types".into(),
        ));
    }
    Ok(())
}

fn validate_application(input: &ClientMetadataInput) -> Result<(), OAuthProviderError> {
    let application_type = input.application_type.as_deref().unwrap_or("web");
    if !["web", "native"].contains(&application_type) {
        return Err(OAuthProviderError::InvalidRequest(
            "application_type must be web or native".into(),
        ));
    }
    for redirect in input.redirect_uris.iter().flatten() {
        validate_redirect_uri(redirect, application_type)?;
    }
    Ok(())
}

fn validate_subject(
    config: &OAuthProviderConfig,
    input: &ClientMetadataInput,
) -> Result<(), OAuthProviderError> {
    let Some(subject_type) = input.subject_type.as_deref() else {
        return Ok(());
    };
    if !matches!(subject_type, "public" | "pairwise") {
        return Err(OAuthProviderError::InvalidRequest(
            "subject_type must be \"public\" or \"pairwise\"".into(),
        ));
    }
    if subject_type != "pairwise" {
        return Ok(());
    }
    if config.pairwise_secret.is_none() {
        return Err(OAuthProviderError::InvalidRequest(
            "pairwise subject_type requires server pairwiseSecret configuration".into(),
        ));
    }
    let mut hosts = BTreeSet::new();
    for redirect in input.redirect_uris.iter().flatten() {
        let url = Url::parse(redirect).map_err(|_| {
            OAuthProviderError::InvalidRedirectUri(format!(
                "redirect URI must be an absolute URI: {redirect}"
            ))
        })?;
        hosts.insert((url.host().map(|host| host.to_string()), url.port()));
    }
    if hosts.len() > 1 {
        return Err(OAuthProviderError::InvalidRequest(
            "pairwise clients with redirect_uris on different hosts require a sector_identifier_uri, which is not yet supported. All redirect_uris must share the same host.".into(),
        ));
    }
    Ok(())
}

fn validate_scopes(
    config: &OAuthProviderConfig,
    input: &ClientMetadataInput,
    source: RegistrationSource,
) -> Result<(), OAuthProviderError> {
    let allowed = if matches!(source, RegistrationSource::Dynamic) {
        registration_scopes(config)
    } else {
        config.scopes.clone()
    }
    .into_iter()
    .collect::<BTreeSet<_>>();
    for scope in input.scope.as_deref().map(split_scopes).unwrap_or_default() {
        if !allowed.contains(&scope) {
            return Err(OAuthProviderError::InvalidScope(format!(
                "cannot request scope {scope}"
            )));
        }
    }
    if matches!(source, RegistrationSource::Dynamic)
        && config.client_registration_require_pkce
        && input.require_pkce == Some(false)
    {
        return Err(OAuthProviderError::InvalidRequest(
            "pkce is required for registered clients.".into(),
        ));
    }
    Ok(())
}

pub(super) fn registration_scopes(config: &OAuthProviderConfig) -> Vec<String> {
    let mut scopes = config
        .client_registration_default_scopes
        .clone()
        .unwrap_or_else(|| config.scopes.clone());
    for scope in &config.client_registration_allowed_scopes {
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    scopes
}

fn validate_redirect_uri(value: &str, application_type: &str) -> Result<(), OAuthProviderError> {
    let url = Url::parse(value).map_err(|_| {
        OAuthProviderError::InvalidRedirectUri(format!(
            "redirect URI must be an absolute URI: {value}"
        ))
    })?;
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(OAuthProviderError::InvalidRedirectUri(format!(
            "redirect URI must not include credentials or a fragment: {value}"
        )));
    }
    let hostname = url.host_str().unwrap_or_default();
    let lowercase_hostname = hostname.to_ascii_lowercase();
    if lowercase_hostname
        .strip_prefix("localhost")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte| byte == b'.'))
    {
        return Err(OAuthProviderError::InvalidRedirectUri(format!(
            "redirect URI localhost must not include trailing dots: {value}"
        )));
    }
    let loopback = hostname == "localhost"
        || hostname
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if application_type == "web" && (url.scheme() != "https" || loopback) {
        return Err(OAuthProviderError::InvalidRedirectUri(format!(
            "web clients require https redirect URIs on non-loopback hosts: {value}"
        )));
    }
    if application_type == "native" {
        if url.scheme() == "https" {
            if loopback {
                return Err(OAuthProviderError::InvalidRedirectUri(format!(
                    "native clients must not use https loopback redirect URIs: {value}"
                )));
            }
            return Ok(());
        }
        if url.scheme() == "http" {
            let exact_loopback = raw_http_hostname(value)
                .is_some_and(|host| matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]"));
            if !exact_loopback {
                return Err(OAuthProviderError::InvalidRedirectUri(format!(
                    "native clients may use http only on the exact loopback hosts localhost, 127.0.0.1, or [::1]: {value}"
                )));
            }
            return Ok(());
        }
        if !valid_private_use_redirect(&url, value) {
            return Err(OAuthProviderError::InvalidRedirectUri(format!(
                "native private-use redirect URI schemes must be well-formed reverse-domain names, omit the naming authority, and must not use a reserved scheme: {value}"
            )));
        }
    }
    Ok(())
}

fn raw_http_hostname(value: &str) -> Option<String> {
    let authority = value
        .strip_prefix("http://")?
        .split(['/', '?', '#'])
        .next()?;
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host_and_port.starts_with('[') {
        let end = host_and_port.find(']')?;
        return Some(host_and_port[..=end].to_ascii_lowercase());
    }
    Some(host_and_port.split(':').next()?.to_ascii_lowercase())
}

fn valid_private_use_redirect(url: &Url, original: &str) -> bool {
    if ["file", "ftp", "mailto", "javascript", "data", "vbscript"].contains(&url.scheme())
        || url.host_str().is_some()
    {
        return false;
    }
    let scheme_specific = original
        .split_once(':')
        .map(|(_, value)| value)
        .unwrap_or_default();
    if !scheme_specific.starts_with('/') || scheme_specific.starts_with("//") {
        return false;
    }
    let segments = url.scheme().split('.').collect::<Vec<_>>();
    segments.len() >= 2
        && segments.iter().enumerate().all(|(index, segment)| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && (index != 0
                    || segment
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphabetic))
        })
}
