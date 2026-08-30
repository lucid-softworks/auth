use super::support;
use crate::{AuthService, SsoPlugin, service::OAuthState};
use axum::{
    Extension,
    extract::{Path, Query},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

mod exchange;

#[derive(Debug, Deserialize)]
pub(super) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub(super) async fn provider(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    handle(&service, &plugin, &headers, &provider_id, query).await
}

pub(super) async fn shared(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let state = match state(&service, &headers, query.state.as_deref()).await {
        Ok(state) => state,
        Err(response) => return *response,
    };
    let Some(reference) = reference(&state) else {
        return redirect_error(
            state.error_url.as_deref().unwrap_or(&state.callback_url),
            "invalid_state",
            "missing_sso_provider_reference",
        );
    };
    let provider_id = reference.provider_id().to_owned();
    handle_with_state(&service, &plugin, &headers, &provider_id, query, state).await
}

async fn handle(
    service: &AuthService,
    plugin: &SsoPlugin,
    headers: &HeaderMap,
    provider_id: &str,
    query: CallbackQuery,
) -> Response {
    let state = match state(service, headers, query.state.as_deref()).await {
        Ok(state) => state,
        Err(response) => return *response,
    };
    handle_with_state(service, plugin, headers, provider_id, query, state).await
}

async fn handle_with_state(
    service: &AuthService,
    plugin: &SsoPlugin,
    headers: &HeaderMap,
    provider_id: &str,
    query: CallbackQuery,
    state: OAuthState,
) -> Response {
    let error_url = state
        .error_url
        .as_deref()
        .unwrap_or(&state.callback_url)
        .to_owned();
    if query.code.as_deref().is_none_or(str::is_empty) || query.error.is_some() {
        let error = query.error.as_deref().unwrap_or("invalid_request");
        let description = query.error_description.as_deref().unwrap_or_else(|| {
            if query.error.is_some() {
                error
            } else {
                "authorization_code_not_found"
            }
        });
        return redirect_error(&error_url, error, description);
    }
    let provider = match plugin.store().find_by_provider_id(provider_id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => return redirect_error(&error_url, "invalid_provider", "provider not found"),
        Err(error) => return support::storage(error),
    };
    let Some(reference) = reference(&state) else {
        return redirect_error(
            &error_url,
            "invalid_state",
            "missing_sso_provider_reference",
        );
    };
    if !reference.is_current(&provider) {
        return redirect_error(
            &error_url,
            "invalid_state",
            "sso_provider_changed_during_authentication",
        );
    }
    if plugin.options().domain_verification && provider.domain_verified != Some(true) {
        return support::error(
            axum::http::StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Provider domain has not been verified",
        );
    }
    if provider
        .oidc_config
        .as_ref()
        .and_then(Value::as_object)
        .is_none()
    {
        return redirect_error(&error_url, "invalid_provider", "provider not found");
    }
    exchange::finish(
        service,
        headers,
        provider,
        query.code.expect("authorization code checked"),
        query.state.unwrap_or_default(),
        state,
        error_url,
    )
    .await
}

async fn state(
    service: &AuthService,
    headers: &HeaderMap,
    token: Option<&str>,
) -> Result<OAuthState, Box<Response>> {
    let default_error = format!("{}/error", support::base_url(service));
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return Err(Box::new(crate::axum::oauth_redirect_error(
            &default_error,
            "invalid_state",
            None,
        )));
    };
    let cookie = service.plugin_cookie(service.oauth_state_cookie_name());
    let raw_cookie = crate::axum::http::cookie_value(headers, &cookie.name);
    let state = service
        .oauth_state(token, raw_cookie.as_deref())
        .await
        .map_err(|_| {
            Box::new(crate::axum::oauth_redirect_error(
                &default_error,
                "invalid_state",
                None,
            ))
        })?;
    let persisted_matches = if service.oauth_state_cookie_name() == "oauth_state" {
        state.oauth_state.as_deref() == Some(token)
    } else {
        state
            .oauth_state
            .as_deref()
            .is_none_or(|persisted| persisted == token)
    };
    let cookie_matches = service.oauth_state_cookie_name() == "oauth_state"
        || service.skip_oauth_state_cookie_check()
        || crate::axum::http::signed_cookie_token(service, headers, &cookie.name).as_deref()
            == Some(token);
    if !persisted_matches || !cookie_matches || state.expires_at < chrono::Utc::now().timestamp_millis()
    {
        return Err(Box::new(crate::axum::oauth_redirect_error(
            state.error_url.as_deref().unwrap_or(&state.callback_url),
            "invalid_state",
            None,
        )));
    }
    Ok(state)
}

fn reference(state: &OAuthState) -> Option<super::super::provider_reference::ProviderReference> {
    state
        .additional_data
        .get("serverContext")
        .and_then(Value::as_object)
        .and_then(|context| context.get("ssoProviderReference"))
        .and_then(super::super::provider_reference::parse)
}

fn redirect_error(base: &str, error: &str, description: &str) -> Response {
    crate::axum::oauth_redirect_error(base, error, Some(description))
}
