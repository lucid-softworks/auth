use super::{redirect_error, support};
use crate::{AuthService, SsoProvider, service::OAuthState};
use axum::{
    http::{HeaderMap, HeaderValue},
    response::Response,
};

pub(super) async fn finish(
    service: &AuthService,
    headers: &HeaderMap,
    mut provider: SsoProvider,
    code: String,
    state_token: String,
    state: OAuthState,
    error_url: String,
) -> Response {
    let Some(config) = provider.oidc_config.as_ref().and_then(serde_json::Value::as_object) else {
        return redirect_error(&error_url, "invalid_provider", "provider not found");
    };
    provider.oidc_config = match super::super::runtime_oidc::ensure(
        service,
        &provider.issuer,
        config,
    )
    .await
    {
        Ok(config) => Some(serde_json::Value::Object(config)),
        Err(error) => return redirect_error(&error_url, "discovery_failed", &error.message),
    };
    let redirect_uri = format!(
        "{}/sso/callback/{}",
        support::base_url(service),
        provider.provider_id
    );
    let dynamic = match super::super::super::oidc_provider::build(&provider, redirect_uri.clone()) {
        Ok(provider) => provider,
        Err(description) => return redirect_error(&error_url, "invalid_provider", description),
    };
    if service.consume_oauth_state(&state_token).await.is_err() {
        return redirect_error(&error_url, "invalid_state", "state_already_used");
    }
    let result = match service
        .oauth_callback_with_provider(
            &dynamic,
            &code,
            state,
            &redirect_uri,
            None,
            None,
            None,
            None,
            crate::axum::http::user_agent(headers),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            return redirect_error(
                &error_url,
                crate::axum::oauth_callback_error_code(&error),
                "token_response_error",
            );
        }
    };
    success(service, headers, &provider.provider_id, result).await
}

async fn success(
    service: &AuthService,
    headers: &HeaderMap,
    provider_id: &str,
    result: crate::OAuthCallbackResult,
) -> Response {
    let location = match HeaderValue::from_str(&result.redirect_url) {
        Ok(location) => location,
        Err(_) => {
            return support::error(
                axum::http::StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid callback URL",
            );
        }
    };
    let response = crate::axum::api_redirect(location);
    let response = match result.session.as_ref() {
        Some(session) => {
            crate::axum::http::with_bound_session_cookie(
                service,
                headers,
                &session.session.user.id,
                &session.token,
                Some(true),
                response,
            )
            .await
        }
        None => response,
    };
    let response = match result.session.as_ref() {
        Some(session) => {
            crate::axum::with_provider_account_cookie(
                service,
                headers,
                &session.session.user.id,
                provider_id,
                response,
            )
            .await
        }
        None => response,
    };
    crate::axum::http::with_cookie(
        response,
        crate::axum::http::serialize_cookie(
            &service.plugin_cookie(service.oauth_state_cookie_name()),
            "",
            Some(0),
        ),
    )
}
