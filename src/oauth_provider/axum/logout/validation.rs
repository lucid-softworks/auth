use super::{input::EndSessionInput, state::ConfirmationState};
use crate::{
    AuthService, JwtAdapterContext,
    oauth_provider::{
        OAuthProviderClient, OAuthProviderConfig, OAuthProviderError, OAuthProviderStore,
        crypto::decrypt_client_secret,
    },
};
use axum::http::HeaderMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Default)]
pub(super) struct LogoutRedirect {
    pub(super) uri: Option<String>,
    pub(super) invalid: bool,
}

pub(super) async fn current_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Result<Option<crate::AuthSession>, OAuthProviderError> {
    let Some(token) = crate::axum::session_token(service, headers) else {
        return Ok(None);
    };
    service
        .session(&token)
        .await
        .map(|session| session.map(|session| session.session))
        .map_err(server_error("Unable to read the current session"))
}

pub(super) async fn hinted_session(
    service: &AuthService,
    session_id: &str,
) -> Result<Option<crate::AuthSession>, OAuthProviderError> {
    service
        .oauth_provider_session_by_id(session_id)
        .await
        .map_err(server_error("Unable to read the hinted session"))
}

pub(super) async fn delete_session(
    service: &AuthService,
    session: &crate::AuthSession,
) -> Result<(), OAuthProviderError> {
    service
        .sign_out(&session.token)
        .await
        .map_err(server_error("Unable to complete logout"))
}

pub(super) async fn logout_client(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    client_id: &str,
) -> Result<OAuthProviderClient, OAuthProviderError> {
    let client = super::super::client::resolve_client(config, store, headers, client_id)
        .await?
        .ok_or_else(|| {
            OAuthProviderError::InvalidClient("The logout client does not exist".into())
        })?;
    validate_logout_client(client)
}

fn validate_logout_client(
    client: OAuthProviderClient,
) -> Result<OAuthProviderClient, OAuthProviderError> {
    if client.disabled {
        return Err(OAuthProviderError::InvalidClient(
            "The logout client is disabled".into(),
        ));
    }
    if client.enable_end_session != Some(true) {
        return Err(OAuthProviderError::UnauthorizedInvalidClient(
            "The client is not allowed to initiate logout".into(),
        ));
    }
    Ok(client)
}

pub(super) async fn resolve_hint_client(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    hint: &str,
    client_id: Option<&str>,
) -> Result<Option<OAuthProviderClient>, OAuthProviderError> {
    let candidate = client_id
        .map(str::to_owned)
        .or_else(|| decoded_client_id(hint));
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let Some(client) =
        super::super::client::resolve_client(config, store, headers, &candidate).await?
    else {
        return Ok(None);
    };
    validate_logout_client(client).map(Some)
}

pub(super) async fn verify_hint(
    service: &AuthService,
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    hint: &str,
    client: &OAuthProviderClient,
) -> Result<Option<Map<String, Value>>, OAuthProviderError> {
    let issuer = super::super::metadata::provider_issuer(service, headers, config);
    let payload = if config.disable_jwt_plugin {
        verify_hmac_hint(service, config, hint, client).await?
    } else {
        let Some(jwt) = service.jwt() else {
            return Err(OAuthProviderError::ServerError(
                "JWT plugin is required for id_token_hint verification".into(),
            ));
        };
        if let Some(remote) = jwt.remote_jwks_url() {
            super::remote_jwks::verify(remote, hint)
                .await
                .unwrap_or(None)
        } else {
            jwt.verify_jwt_signature(&jwt_context(headers), hint)
                .await
                .map_err(server_error("Unable to verify the id_token_hint"))?
        }
    };
    Ok(payload.filter(|payload| valid_hint_claims(payload, &issuer, &client.client_id)))
}

async fn verify_hmac_hint(
    service: &AuthService,
    config: &OAuthProviderConfig,
    hint: &str,
    client: &OAuthProviderClient,
) -> Result<Option<Map<String, Value>>, OAuthProviderError> {
    let Some(stored) = client.client_secret.as_deref() else {
        return Ok(None);
    };
    let secret = decrypt_client_secret(service, config, stored)
        .await
        .map_err(server_error("Unable to verify the id_token_hint"))?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    Ok(decode::<Map<String, Value>>(
        hint,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()
    .map(|token| token.claims))
}

fn valid_hint_claims(payload: &Map<String, Value>, issuer: &str, client_id: &str) -> bool {
    payload.get("iss").and_then(Value::as_str) == Some(issuer)
        && audiences(payload.get("aud")).contains(&client_id)
        && payload
            .get("sid")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        && payload
            .get("sub")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
}

fn audiences(value: Option<&Value>) -> Vec<&str> {
    match value {
        Some(Value::String(value)) => vec![value],
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

pub(super) fn validate_redirect(
    client: &OAuthProviderClient,
    input: &EndSessionInput,
) -> LogoutRedirect {
    registered_redirect(
        client,
        input.post_logout_redirect_uri.as_deref(),
        input.state.as_deref(),
    )
}

pub(super) async fn confirmed_redirect(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    state: &ConfirmationState,
) -> LogoutRedirect {
    if state.redirect_invalid {
        return LogoutRedirect {
            invalid: true,
            ..Default::default()
        };
    }
    let (Some(client_id), Some(uri)) = (
        state.client_id.as_deref(),
        state.post_logout_redirect_uri.as_deref(),
    ) else {
        return LogoutRedirect::default();
    };
    match logout_client(config, store, headers, client_id).await {
        Ok(client) => registered_redirect(&client, Some(uri), state.state.as_deref()),
        Err(_) => LogoutRedirect {
            invalid: true,
            ..Default::default()
        },
    }
}

fn registered_redirect(
    client: &OAuthProviderClient,
    requested: Option<&str>,
    state: Option<&str>,
) -> LogoutRedirect {
    let Some(requested) = requested else {
        return LogoutRedirect::default();
    };
    if !client
        .post_logout_redirect_uris
        .as_ref()
        .is_some_and(|registered| registered.iter().any(|uri| uri == requested))
    {
        return LogoutRedirect {
            invalid: true,
            ..Default::default()
        };
    }
    let Ok(mut uri) = url::Url::parse(requested) else {
        return LogoutRedirect {
            invalid: true,
            ..Default::default()
        };
    };
    if let Some(state) = state {
        let retained = uri
            .query_pairs()
            .filter(|(name, _)| name != "state")
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        let mut query = uri.query_pairs_mut();
        query.clear().extend_pairs(retained);
        query.append_pair("state", state);
    }
    LogoutRedirect {
        uri: Some(uri.into()),
        invalid: false,
    }
}

fn decoded_client_id(hint: &str) -> Option<String> {
    let payload = jsonwebtoken::dangerous::insecure_decode::<Value>(hint)
        .ok()?
        .claims;
    if let Some(audience) = payload.get("aud").and_then(Value::as_str) {
        return (!audience.is_empty()).then(|| audience.to_owned());
    }
    if let Some(authorized) = payload.get("azp").and_then(Value::as_str) {
        return (!authorized.is_empty()).then(|| authorized.to_owned());
    }
    let audiences = payload.get("aud")?.as_array()?;
    (audiences.len() == 1)
        .then(|| audiences[0].as_str().map(str::to_owned))
        .flatten()
}

fn jwt_context(headers: &HeaderMap) -> JwtAdapterContext {
    JwtAdapterContext {
        method: Some("POST".into()),
        path: Some("/oauth2/end-session".into()),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect(),
        ..Default::default()
    }
}

fn server_error(message: &'static str) -> impl FnOnce(crate::AuthError) -> OAuthProviderError {
    move |_| OAuthProviderError::ServerError(message.into())
}
