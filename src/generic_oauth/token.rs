use super::{
    provider::GenericOAuthProvider,
    types::{GenericOAuthError, GenericOAuthRefreshContext, GenericOAuthTokenRequest},
};
use crate::{
    AuthError, OAuthClientAssertionContext, OAuthGrantType, OAuthRefreshContext, OAuthTokens,
    TokenEndpointAuth,
};
use base64::Engine;
use chrono::{Duration, Utc};
use serde_json::Value;
use std::collections::BTreeMap;

const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

pub(super) async fn exchange_code(
    provider: &GenericOAuthProvider,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    device_id: Option<&str>,
) -> Result<OAuthTokens, AuthError> {
    if let Some(callback) = &provider.config.get_token {
        let mut tokens = callback
            .exchange(GenericOAuthTokenRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                code_verifier: provider
                    .config
                    .pkce
                    .unwrap_or(true)
                    .then(|| code_verifier.into()),
                device_id: device_id.map(str::to_owned),
            })
            .await?;
        apply_default_expiry(provider, &mut tokens);
        return Ok(tokens);
    }
    let redirect_uri = provider
        .config
        .redirect_uri
        .as_deref()
        .filter(|uri| !uri.is_empty())
        .unwrap_or(redirect_uri)
        .to_owned();
    let mut params = BTreeMap::from([
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code.into()),
        ("redirect_uri".into(), redirect_uri),
    ]);
    if provider.config.pkce.unwrap_or(true) {
        params.insert("code_verifier".into(), code_verifier.into());
    }
    if let Some(device_id) = device_id {
        params.insert("device_id".into(), device_id.into());
    }
    for (name, value) in &provider.config.token_url_params {
        params.entry(name.clone()).or_insert_with(|| value.clone());
    }
    request_tokens(
        provider,
        params,
        OAuthGrantType::AuthorizationCode,
        &provider.config.authorization_headers,
    )
    .await
}

pub(super) async fn refresh(
    provider: &GenericOAuthProvider,
    refresh_token: &str,
    context: &OAuthRefreshContext,
) -> Result<OAuthTokens, AuthError> {
    let mut params = provider.config.refresh_token_params.clone();
    if let Some(resolver) = &provider.config.refresh_token_params_resolver {
        params.extend(
            resolver
                .refresh_params(&GenericOAuthRefreshContext {
                    request: context.request.clone(),
                })
                .await?,
        );
    }
    for blocked in [
        "grant_type",
        "refresh_token",
        "__proto__",
        "constructor",
        "prototype",
    ] {
        params.remove(blocked);
    }
    params.insert("grant_type".into(), "refresh_token".into());
    params.insert("refresh_token".into(), refresh_token.into());
    request_tokens(
        provider,
        params,
        OAuthGrantType::RefreshToken,
        &BTreeMap::new(),
    )
    .await
}

async fn request_tokens(
    provider: &GenericOAuthProvider,
    mut params: BTreeMap<String, String>,
    grant_type: OAuthGrantType,
    headers: &BTreeMap<String, String>,
) -> Result<OAuthTokens, AuthError> {
    let endpoint = provider
        .config
        .token_url
        .as_deref()
        .ok_or(GenericOAuthError::TokenUrlNotFound)?;
    let auth = token_auth(provider);
    let mut request_headers = headers.clone();
    apply_token_auth(
        &auth,
        &mut TokenAuthRequest {
            has_explicit_auth: provider.config.token_endpoint_auth.is_some(),
            client_id: &provider.config.client_id,
            client_secret: provider.config.client_secret.as_deref(),
            endpoint,
            grant_type,
            params: &mut params,
            headers: &mut request_headers,
        },
    )
    .await?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AuthError::OAuthInvalidCode)?;
    let mut request = client
        .post(endpoint)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .body(body);
    for (name, value) in request_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .map_err(|_| AuthError::OAuthInvalidCode)?;
    if !response.status().is_success() || response.status().is_redirection() {
        return Err(AuthError::OAuthInvalidCode);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| AuthError::OAuthInvalidCode)?;
    let value: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        Value::Object(
            url::form_urlencoded::parse(&bytes)
                .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
                .collect(),
        )
    });
    let mut tokens = crate::oauth::parse_token_response(value)?;
    apply_default_expiry(provider, &mut tokens);
    Ok(tokens)
}

fn token_auth(provider: &GenericOAuthProvider) -> TokenEndpointAuth {
    provider
        .config
        .token_endpoint_auth
        .clone()
        .unwrap_or_else(|| {
            if provider.config.authentication_basic {
                TokenEndpointAuth::ClientSecretBasic
            } else if provider.config.client_secret.is_some() {
                TokenEndpointAuth::ClientSecretPost
            } else {
                TokenEndpointAuth::None
            }
        })
}

fn apply_default_expiry(provider: &GenericOAuthProvider, tokens: &mut OAuthTokens) {
    if tokens.access_token_expires_at.is_none()
        && let Some(seconds) = provider.config.access_token_expires_in
        && seconds != 0
    {
        tokens.access_token_expires_at = Some(Utc::now() + Duration::seconds(seconds));
    }
}

struct TokenAuthRequest<'a> {
    has_explicit_auth: bool,
    client_id: &'a str,
    client_secret: Option<&'a str>,
    endpoint: &'a str,
    grant_type: OAuthGrantType,
    params: &'a mut BTreeMap<String, String>,
    headers: &'a mut BTreeMap<String, String>,
}

async fn apply_token_auth(
    auth: &TokenEndpointAuth,
    request: &mut TokenAuthRequest<'_>,
) -> Result<(), AuthError> {
    if apply_manual_assertion(
        request.has_explicit_auth,
        request.client_id,
        request.client_secret,
        request.params,
    )? {
        return Ok(());
    }
    match auth {
        TokenEndpointAuth::ClientSecretPost => {
            apply_secret_post(request.client_id, request.client_secret, request.params)?;
        }
        TokenEndpointAuth::ClientSecretBasic => {
            apply_secret_basic(
                request.client_id,
                request.client_secret,
                request.params,
                request.headers,
            )?;
        }
        TokenEndpointAuth::None => {
            reject_client_secret("none", request.client_secret, request.params)?;
            require_client_id("none", request.client_id)?;
            request
                .params
                .insert("client_id".into(), request.client_id.into());
        }
        TokenEndpointAuth::PrivateKeyJwt(assertion) => {
            reject_client_secret("private_key_jwt", request.client_secret, request.params)?;
            require_client_id("private_key_jwt", request.client_id)?;
            let assertion = assertion
                .client_assertion(OAuthClientAssertionContext {
                    client_id: request.client_id.into(),
                    token_endpoint: request.endpoint.into(),
                    grant_type: request.grant_type,
                })
                .await?;
            request
                .params
                .insert("client_id".into(), request.client_id.into());
            request.params.insert("client_assertion".into(), assertion);
            request
                .params
                .insert("client_assertion_type".into(), CLIENT_ASSERTION_TYPE.into());
        }
    }
    Ok(())
}

fn apply_manual_assertion(
    has_explicit_auth: bool,
    client_id: &str,
    client_secret: Option<&str>,
    params: &mut BTreeMap<String, String>,
) -> Result<bool, AuthError> {
    let has_assertion = params.contains_key("client_assertion");
    let has_assertion_type = params.contains_key("client_assertion_type");
    if has_assertion != has_assertion_type {
        return Err(AuthError::InvalidConfiguration(
            "client_assertion and client_assertion_type must both be provided".into(),
        ));
    }
    if !has_assertion {
        return Ok(false);
    }
    if has_explicit_auth {
        return Err(AuthError::InvalidConfiguration(
            "client_assertion body parameters cannot be combined with tokenEndpointAuth".into(),
        ));
    }
    reject_client_secret("private_key_jwt", client_secret, params)?;
    require_client_id("private_key_jwt", client_id)?;
    params.insert("client_id".into(), client_id.into());
    Ok(true)
}

fn apply_secret_post(
    client_id: &str,
    client_secret: Option<&str>,
    params: &mut BTreeMap<String, String>,
) -> Result<(), AuthError> {
    let secret = require_client_secret("client_secret_post", client_secret)?;
    require_client_id("client_secret_post", client_id)?;
    params.insert("client_id".into(), client_id.into());
    params.insert("client_secret".into(), secret.into());
    Ok(())
}

fn apply_secret_basic(
    client_id: &str,
    client_secret: Option<&str>,
    params: &BTreeMap<String, String>,
    headers: &mut BTreeMap<String, String>,
) -> Result<(), AuthError> {
    if params.contains_key("client_secret") {
        return Err(AuthError::InvalidConfiguration(
            "client_secret_basic token endpoint authentication cannot be combined with client_secret body parameters".into(),
        ));
    }
    let secret = require_client_secret("client_secret_basic", client_secret)?;
    require_client_id("client_secret_basic", client_id)?;
    let credentials = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        form_component(client_id),
        form_component(secret)
    ));
    headers.insert("authorization".into(), format!("Basic {credentials}"));
    Ok(())
}

fn require_client_secret<'a>(
    method: &str,
    client_secret: Option<&'a str>,
) -> Result<&'a str, AuthError> {
    client_secret.ok_or_else(|| {
        AuthError::InvalidConfiguration(format!(
            "{method} token endpoint authentication requires clientSecret"
        ))
    })
}

fn reject_client_secret(
    method: &str,
    client_secret: Option<&str>,
    params: &BTreeMap<String, String>,
) -> Result<(), AuthError> {
    if client_secret.is_some() || params.contains_key("client_secret") {
        return Err(AuthError::InvalidConfiguration(format!(
            "{method} token endpoint authentication cannot be combined with clientSecret"
        )));
    }
    Ok(())
}

fn require_client_id(method: &str, client_id: &str) -> Result<(), AuthError> {
    if client_id.is_empty() {
        return Err(AuthError::InvalidConfiguration(format!(
            "{method} token endpoint authentication requires clientId"
        )));
    }
    Ok(())
}

fn form_component(value: &str) -> String {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("v", value)
        .finish();
    encoded.strip_prefix("v=").unwrap_or_default().to_owned()
}
