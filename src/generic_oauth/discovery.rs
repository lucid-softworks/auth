use super::{provider::GenericOAuthProvider, types::GenericOAuthConfig};
use crate::{AuthError, OidcConfig, TokenEndpointAuth};
use serde::Deserialize;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    jwks_uri: Option<String>,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

pub(super) async fn resolve_providers(
    configs: Vec<GenericOAuthConfig>,
) -> Result<Vec<Arc<GenericOAuthProvider>>, AuthError> {
    let mut providers = Vec::with_capacity(configs.len());
    for config in configs {
        providers.push(Arc::new(resolve_provider(config).await?));
    }
    Ok(providers)
}

async fn resolve_provider(
    mut config: GenericOAuthConfig,
) -> Result<GenericOAuthProvider, AuthError> {
    if config.client_secret.as_deref() == Some("") {
        config.client_secret = None;
    }
    validate_auth(&config)?;
    let mut issuer = None;
    let mut oidc = None;
    let mut is_oidc = false;
    if let Some(discovery_url) = config.discovery_url.as_deref() {
        let discovery = fetch_discovery(discovery_url, &config.discovery_headers).await;
        if let Some(document) = discovery {
            let discovered_issuer = document
                .issuer
                .as_deref()
                .filter(|issuer| !issuer.is_empty())
                .map(str::to_owned);
            if discovered_issuer.is_none() && !has_account_issuer(&config) {
                return invalid(format!(
                    "Provider \"{}\": discovery did not return an issuer. Configure accountIssuer explicitly to establish a stable account namespace.",
                    config.provider_id
                ));
            }
            config.authorization_url = config.authorization_url.or(document.authorization_endpoint);
            config.token_url = config.token_url.or(document.token_endpoint);
            config.user_info_url = config.user_info_url.or(document.userinfo_endpoint);
            config.end_session_endpoint = config
                .end_session_endpoint
                .or(document.end_session_endpoint);
            issuer.clone_from(&discovered_issuer);
            let algorithms = document
                .id_token_signing_alg_values_supported
                .unwrap_or_default();
            is_oidc = !algorithms.is_empty();
            if let (Some(discovered_issuer), Some(jwks_uri)) = (
                discovered_issuer.as_deref(),
                document.jwks_uri.as_deref().filter(|uri| !uri.is_empty()),
            ) {
                let jwks_url = Url::parse(discovery_url)
                    .and_then(|base| base.join(jwks_uri))
                    .map_err(|_| {
                        AuthError::InvalidConfiguration(format!(
                            "Provider \"{}\": invalid jwks_uri \"{jwks_uri}\" in discovery document.",
                            config.provider_id
                        ))
                    })?;
                oidc = Some(OidcConfig {
                    jwks_url: jwks_url.into(),
                    issuers: vec![discovered_issuer.to_owned()],
                    audiences: vec![config.client_id.clone()],
                    algorithms,
                    requires_nonce: !config.disable_id_token_nonce_binding,
                    nonce_sha256_fallback: false,
                    maximum_age: None,
                    dynamic_issuer_template: None,
                });
            }
        } else if !has_account_issuer(&config) {
            return invalid(format!(
                "Provider \"{}\": discovery returned no valid data. Provider initialization stopped to keep its account issuer stable.",
                config.provider_id
            ));
        } else if config.authorization_url.is_none() || config.token_url.is_none() {
            eprintln!(
                "Provider \"{}\": discovery returned no data and no explicit endpoints configured. OAuth sign-in will fail for this provider.",
                config.provider_id
            );
        }
    }
    if config.require_id_token_verification && oidc.is_none() {
        return invalid(format!(
            "Provider \"{}\": requires verified ID tokens, but discovery did not provide a usable issuer and jwks_uri.",
            config.provider_id
        ));
    }
    Ok(GenericOAuthProvider::new(config, issuer, is_oidc, oidc))
}

fn has_account_issuer(config: &GenericOAuthConfig) -> bool {
    config.account_issuer_resolver.is_some()
        || config
            .account_issuer
            .as_deref()
            .is_some_and(|issuer| !issuer.is_empty())
}

async fn fetch_discovery(
    url: &str,
    headers: &std::collections::BTreeMap<String, String>,
) -> Option<DiscoveryDocument> {
    let mut request = reqwest::Client::new().get(url);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let document = response.json::<DiscoveryDocument>().await.ok()?;
    if let Some(issuer) = document
        .issuer
        .as_deref()
        .filter(|issuer| !issuer.is_empty())
        && Url::parse(issuer).is_err()
    {
        return None;
    }
    Some(document)
}

fn validate_auth(config: &GenericOAuthConfig) -> Result<(), AuthError> {
    match (&config.client_secret, &config.token_endpoint_auth) {
        (Some(_), Some(TokenEndpointAuth::None)) => invalid(format!(
            "Provider \"{}\": tokenEndpointAuth.method \"none\" cannot be combined with clientSecret",
            config.provider_id
        )),
        (Some(_), Some(TokenEndpointAuth::PrivateKeyJwt(_))) => invalid(format!(
            "Provider \"{}\": tokenEndpointAuth.method \"private_key_jwt\" cannot be combined with clientSecret",
            config.provider_id
        )),
        (None, Some(TokenEndpointAuth::ClientSecretBasic)) => invalid(format!(
            "Provider \"{}\": tokenEndpointAuth.method \"client_secret_basic\" requires clientSecret",
            config.provider_id
        )),
        (None, Some(TokenEndpointAuth::ClientSecretPost)) => invalid(format!(
            "Provider \"{}\": tokenEndpointAuth.method \"client_secret_post\" requires clientSecret",
            config.provider_id
        )),
        (None, None) if config.authentication_basic => invalid(format!(
            "Provider \"{}\": authentication \"basic\" requires clientSecret",
            config.provider_id
        )),
        _ => Ok(()),
    }
}

fn invalid<T>(message: String) -> Result<T, AuthError> {
    Err(AuthError::InvalidConfiguration(message))
}
