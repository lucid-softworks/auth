mod config;
mod profile;
mod security;

use super::{callback, support};
use crate::{AuthService, SsoPlugin, service::OAuthState};
use axum::{
    Extension,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use samlet::raw::{Binding, HttpRequest};
use samlet::SsoSession;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

const REQUEST_PREFIX: &str = "saml-authn-request:";
const ASSERTION_PREFIX: &str = "saml-used-assertion:";

#[derive(Debug, Deserialize)]
pub(super) struct AcsBody {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AcsQuery {
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

pub(super) async fn post(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<AcsBody>,
) -> Response {
    if body.saml_response.len() > plugin.options().saml_max_response_size {
        return support::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!(
                "SAML response exceeds maximum allowed size ({} bytes)",
                plugin.options().saml_max_response_size
            ),
        );
    }
    let relay_state = match body.relay_state.as_deref().filter(|state| !state.is_empty()) {
        Some(state) => state,
        None => {
            return support::error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "State error: failed to validate relay state",
            );
        }
    };
    let state = match security::load_state(&service, relay_state).await {
        Ok(state) => state,
        Err(response) => return *response,
    };
    finish(
        &service,
        &plugin,
        &headers,
        &provider_id,
        relay_state,
        body.saml_response,
        state,
    )
    .await
}

pub(super) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<AcsQuery>,
) -> Response {
    if crate::axum::http::current_session_cache_first(&service, &headers)
        .await
        .is_none()
    {
        return callback::redirect_error(
            &format!("{}/error", support::base_url(&service)),
            "invalid_request",
            "invalid_request",
        );
    }
    let target = query.relay_state.filter(|target| {
        crate::axum::validate_trusted_origin_value(&service, &headers, target).is_ok()
    });
    let target = target.unwrap_or_else(|| support::base_url(&service));
    match HeaderValue::from_str(&target) {
        Ok(location) => crate::axum::api_redirect(location),
        Err(_) => support::error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid callback URL"),
    }
}

async fn finish(
    service: &AuthService,
    plugin: &SsoPlugin,
    headers: &HeaderMap,
    provider_id: &str,
    relay_state: &str,
    saml_response: String,
    state: OAuthState,
) -> Response {
    let error_url = state
        .error_url
        .as_deref()
        .unwrap_or(&state.callback_url)
        .to_owned();
    let Some((request_id, state_reference)) = security::state_context(&state) else {
        return failure(&error_url, "invalid_state", "sso_provider_reference_missing_or_invalid");
    };
    let (provider, session) = match validate(
        service,
        plugin,
        provider_id,
        relay_state,
        &request_id,
        &state_reference,
        &error_url,
        saml_response,
    )
    .await
    {
        Ok(validated) => validated,
        Err(response) => return *response,
    };
    let Some(saml_config) = provider.saml_config.as_ref().and_then(Value::as_object) else {
        return failure(&error_url, "invalid_provider", "provider not found");
    };
    let user_info = match profile::user_info(
        &session,
        saml_config,
        plugin.options().trust_email_verified,
    ) {
        Ok(user_info) => user_info,
        Err(()) => {
            return failure(
                &error_url,
                "invalid_saml_response",
                "Unable to extract user ID or email from SAML response",
            );
        }
    };
    let result = match service
        .finish_sso_sign_in(
            provider_id,
            user_info,
            state,
            plugin.options().disable_implicit_sign_up,
            crate::axum::http::user_agent(headers),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            let (code, description) = callback::exchange::callback_error(&error);
            return failure(&error_url, code, description);
        }
    };
    let response = callback::exchange::success(service, headers, provider_id, result).await;
    crate::axum::http::with_cookie(
        response,
        crate::axum::http::serialize_cookie(
            &service.plugin_cookie("relay_state"),
            "",
            Some(0),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
async fn validate(
    service: &AuthService,
    plugin: &SsoPlugin,
    provider_id: &str,
    relay_state: &str,
    request_id: &str,
    state_reference: &super::super::provider_reference::ProviderReference,
    error_url: &str,
    saml_response: String,
) -> Result<(crate::SsoProvider, SsoSession), Box<Response>> {
    let provider = security::current_provider(plugin, provider_id, state_reference, error_url).await?;
    let config = provider
        .saml_config
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| Box::new(failure(error_url, "invalid_provider", "provider not found")))?;
    let entities = config::entities(service, &provider, config, plugin.options()).map_err(|()| {
        Box::new(failure(
            error_url,
            "invalid_saml_response",
            "Invalid SAML response",
        ))
    })?;
    let session = parse_session(
        entities,
        relay_state,
        request_id,
        saml_response,
        plugin.options(),
    )
    .map_err(|message| {
        Box::new(failure(
            error_url,
            "invalid_saml_response",
            message.as_deref().unwrap_or("Invalid SAML response"),
        ))
    })?;
    let provider = security::current_provider(plugin, provider_id, state_reference, error_url).await?;
    security::consume_bindings(
        service,
        provider_id,
        relay_state,
        request_id,
        state_reference,
        &session,
        plugin.options().saml_clock_skew_ms,
        error_url,
    )
    .await?;
    Ok((provider, session))
}

fn parse_session(
    entities: config::SamlEntities,
    relay_state: &str,
    request_id: &str,
    saml_response: String,
    options: &crate::SsoOptions,
) -> Result<SsoSession, Option<String>> {
    let normalized = saml_response
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();
    let request = HttpRequest::post(vec![
        ("SAMLResponse".into(), normalized),
        ("RelayState".into(), relay_state.into()),
    ]);
    let parsed = entities
        .sp
        .parse_login_response_with_request_id(
            &entities.idp,
            Binding::Post,
            &request,
            request_id,
        )
        .map_err(|_| None)?;
    let session = SsoSession::try_from(parsed).map_err(|_| None)?;
    crate::sso::validate_response_algorithms(&session, &options.saml_algorithms)
        .map_err(|error| Some(error.message))?;
    if options.saml_require_timestamps
        && session.not_before().is_none()
        && session.not_on_or_after().is_none()
    {
        return Err(Some(
            "SAML assertion missing required timestamp conditions".into(),
        ));
    }
    Ok(session)
}

fn failure(base: &str, error: &str, description: &str) -> Response {
    callback::redirect_error(base, error, description)
}
