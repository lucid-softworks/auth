use super::{provider::GenericOAuthProvider, types::GenericOAuthError};
use crate::{AuthError, AuthorizationRequest};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use url::Url;

pub(super) fn create_url(
    provider: &GenericOAuthProvider,
    request: &AuthorizationRequest,
) -> Result<Url, AuthError> {
    let endpoint = provider
        .config
        .authorization_url
        .as_deref()
        .ok_or(GenericOAuthError::InvalidOAuthConfiguration)?;
    let mut url = Url::parse(endpoint).map_err(|_| GenericOAuthError::InvalidOAuthConfiguration)?;
    if provider.config.client_id.is_empty() {
        return Err(GenericOAuthError::InvalidOAuthConfiguration.into());
    }
    let mut additional = provider.config.authorization_url_params.clone();
    additional.extend(request.additional_params.clone());
    for reserved in [
        "state",
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "scope",
    ] {
        additional.remove(reserved);
    }
    let mut parameters = base_parameters(provider, request);
    if provider.config.pkce.unwrap_or(true) {
        let challenge = Sha256::digest(request.code_verifier.as_bytes());
        parameters.insert(
            "code_challenge".into(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        );
        parameters.insert("code_challenge_method".into(), "S256".into());
    }
    parameters.extend(additional);
    let existing = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .chain(parameters)
        .collect::<BTreeMap<_, _>>();
    url.set_query(None);
    url.query_pairs_mut().extend_pairs(existing);
    Ok(url)
}

fn base_parameters(
    provider: &GenericOAuthProvider,
    request: &AuthorizationRequest,
) -> BTreeMap<String, String> {
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "response_type".into(),
        provider
            .config
            .response_type
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| "code".into()),
    );
    parameters.insert("client_id".into(), provider.config.client_id.clone());
    parameters.insert("state".into(), request.state.clone());
    parameters.insert(
        "redirect_uri".into(),
        provider
            .config
            .redirect_uri
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| request.redirect_uri.clone()),
    );
    let mut scopes = request.scopes.clone().unwrap_or_default();
    scopes.extend(provider.config.scopes.iter().cloned());
    if provider.is_oidc && !scopes.iter().any(|scope| scope == "openid") {
        scopes.insert(0, "openid".into());
    }
    if !scopes.is_empty() {
        parameters.insert("scope".into(), scopes.join(" "));
    }
    for (name, value) in [
        ("prompt", provider.config.prompt.as_ref()),
        ("access_type", provider.config.access_type.as_ref()),
        ("response_mode", provider.config.response_mode.as_ref()),
        ("login_hint", request.login_hint.as_ref()),
        ("nonce", request.id_token_nonce.as_ref()),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            parameters.insert(name.into(), value.clone());
        }
    }
    parameters
}
