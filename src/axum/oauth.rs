use super::{
    body::OptionalBetterAuthBody,
    http::{
        PeerAddress, auth_error, client_ip, cookie_value, serialize_cookie, signed_cookie_token,
        user_agent, with_account_cookie, with_bound_session_cookie, with_cookie,
    },
};
use crate::{AuthError, AuthService};
use axum::{
    Extension, Router,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue},
    response::Response,
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/sign-in/social",
            post(super::oauth_sign_in::sign_in_social),
        )
        .route(
            "/callback/{provider}",
            axum::routing::get(oauth_callback).post(oauth_callback_post),
        )
}

#[derive(Deserialize, Serialize, Default)]
pub(crate) struct OAuthCallbackQuery {
    pub(super) code: Option<String>,
    pub(crate) error: Option<String>,
    device_id: Option<String>,
    error_description: Option<String>,
    pub(super) state: Option<String>,
    pub(crate) user: Option<String>,
    iss: Option<String>,
}

async fn oauth_callback_post(
    Extension(service): Extension<Arc<AuthService>>,
    Path(provider): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
    OptionalBetterAuthBody(input): OptionalBetterAuthBody<OAuthCallbackQuery>,
) -> Response {
    let callback = match service.oauth_callback_url(&provider) {
        Ok(callback) => callback,
        Err(error) => return auth_error(error),
    };
    let merged = OAuthCallbackQuery {
        code: query.code.or(input.code),
        error: query.error.or(input.error),
        device_id: query.device_id.or(input.device_id),
        error_description: query.error_description.or(input.error_description),
        state: query.state.or(input.state),
        user: query.user.or(input.user),
        iss: query.iss.or(input.iss),
    };
    if let Some(response) =
        super::oauth_proxy::provider_callback(&service, &provider, &merged).await
    {
        return response;
    }
    let query = match serde_urlencoded::to_string(merged) {
        Ok(query) => query,
        Err(_) => {
            return redirect_error(
                &format!("{callback}/error"),
                "invalid_callback_request",
                None,
            );
        }
    };
    redirect(&format!("{callback}?{query}"))
}

async fn oauth_callback(
    Extension(service): Extension<Arc<AuthService>>,
    Path(provider_id): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
    peer: PeerAddress,
    headers: HeaderMap,
) -> Response {
    let default_error_url = service
        .oauth_base_url()
        .map(|base| format!("{base}/error"))
        .unwrap_or_else(|_| "/api/auth/error".into());
    if let Some(response) =
        super::oauth_proxy::provider_callback(&service, &provider_id, &query).await
    {
        return response;
    }
    if let Some(response) = super::oauth_state::idp_initiated_response(
        &service,
        &provider_id,
        &query,
        &default_error_url,
    )
    .await
    {
        return response;
    }
    let Some(state_token) = query.state.as_deref() else {
        return redirect_error(&default_error_url, "state_not_found", None);
    };
    let (state, account_user_id, error_url) =
        match validated_callback_state(&service, &headers, state_token, &default_error_url).await {
            Ok(state) => state,
            Err(response) => return response,
        };
    if let Some(error) = query.error.as_deref() {
        return clear_state_cookie(
            &service,
            redirect_error(&error_url, error, query.error_description.as_deref()),
        );
    }
    let Some(code) = query.code.as_deref() else {
        return clear_state_cookie(&service, redirect_error(&error_url, "no_code", None));
    };
    let provider_user = query
        .user
        .as_deref()
        .and_then(|value| serde_json::from_str::<Value>(value).ok());
    match service
        .oauth_callback(
            &provider_id,
            code,
            state,
            query.iss.as_deref(),
            query.device_id.as_deref(),
            provider_user.as_ref(),
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => {
            oauth_success_response(&service, &headers, &provider_id, account_user_id, result).await
        }
        Err(error) => clear_state_cookie(
            &service,
            redirect_error(&error_url, callback_error_code(&error), None),
        ),
    }
}

// Keeping Axum's concrete response here preserves the callback's redirect and
// cookie headers without adding a boxed error type to this internal hot path.
#[allow(clippy::result_large_err)]
async fn validated_callback_state(
    service: &AuthService,
    headers: &HeaderMap,
    state_token: &str,
    default_error_url: &str,
) -> Result<(crate::service::OAuthState, Option<String>, String), Response> {
    let state_cookie_name = service.oauth_state_cookie_name();
    let state_cookie = service.plugin_cookie(state_cookie_name);
    let raw_state_cookie = cookie_value(headers, &state_cookie.name);
    let state = match service
        .oauth_state(state_token, raw_state_cookie.as_deref())
        .await
    {
        Ok(state) => state,
        Err(AuthError::OAuthStateInvalid) => {
            return Err(clear_state_cookie(
                service,
                redirect_error(default_error_url, "state_invalid", None),
            ));
        }
        Err(AuthError::OAuthStateMismatch) => {
            return Err(redirect_error(default_error_url, "state_mismatch", None));
        }
        Err(_) => {
            return Err(clear_state_cookie(
                service,
                redirect_error(default_error_url, "internal_server_error", None),
            ));
        }
    };
    let account_user_id = state.link.as_ref().map(|link| link.user_id.clone());
    let error_url = state
        .error_url
        .clone()
        .unwrap_or_else(|| default_error_url.to_owned());
    let persisted_state_matches = if state_cookie_name == "oauth_state" {
        state.oauth_state.as_deref() == Some(state_token)
    } else {
        state
            .oauth_state
            .as_deref()
            .is_none_or(|bound| bound == state_token)
    };
    let cookie_matches = state_cookie_name == "oauth_state"
        || service.skip_oauth_state_cookie_check()
        || signed_cookie_token(service, headers, &state_cookie.name).as_deref()
            == Some(state_token);
    if !persisted_state_matches || !cookie_matches {
        return Err(clear_state_cookie(
            service,
            redirect_error(&error_url, "state_mismatch", None),
        ));
    }
    if state.expires_at < chrono::Utc::now().timestamp_millis() {
        return Err(clear_state_cookie(
            service,
            redirect_error(&error_url, "state_mismatch", None),
        ));
    }
    if let Err(error) = service.consume_oauth_state(state_token).await {
        let code = if matches!(error, AuthError::OAuthStateMismatch) {
            "state_mismatch"
        } else {
            "internal_server_error"
        };
        return Err(clear_state_cookie(
            service,
            redirect_error(&error_url, code, None),
        ));
    }
    Ok((state, account_user_id, error_url))
}

async fn oauth_success_response(
    service: &AuthService,
    headers: &HeaderMap,
    provider_id: &str,
    linked_user_id: Option<String>,
    result: crate::OAuthCallbackResult,
) -> Response {
    let response = redirect(&result.redirect_url);
    let response = match result.session {
        Some(ref session) => {
            with_bound_session_cookie(
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
    let user_id = result
        .session
        .as_ref()
        .map(|session| session.session.user.id.clone())
        .or(linked_user_id);
    let response = match user_id {
        Some(user_id) => {
            with_provider_account_cookie(service, headers, &user_id, provider_id, response).await
        }
        None => response,
    };
    clear_state_cookie(service, response)
}

pub(crate) async fn with_provider_account_cookie(
    service: &AuthService,
    headers: &HeaderMap,
    user_id: &str,
    provider_id: &str,
    response: Response,
) -> Response {
    if !service.account_cookie_enabled() {
        return response;
    }
    match service
        .account_cookie_for_provider(user_id, provider_id)
        .await
    {
        Ok(Some(account)) => with_account_cookie(service, headers, account, response),
        Ok(None) => response,
        Err(error) => auth_error(error),
    }
}

pub(crate) fn callback_error_code(error: &AuthError) -> &'static str {
    match error {
        AuthError::OAuthInvalidCode => "invalid_code",
        AuthError::OAuthProviderNotFound => "oauth_provider_not_found",
        AuthError::OAuthIssuerMismatch => "issuer_mismatch",
        AuthError::OAuthNonceBindingMissing => "nonce_binding_missing",
        AuthError::OAuthStateMismatch => "state_mismatch",
        AuthError::OAuthEmailNotFound => "email_not_found",
        AuthError::OAuthAccountNotLinked => "account_not_linked",
        AuthError::OAuthSignupDisabled => "signup_disabled",
        AuthError::OAuthUnableToUpdateAccount => "unable_to_update_account",
        AuthError::OAuthUnableToCreateUser => "unable_to_create_user",
        AuthError::OAuthUnableToCreateSession => "unable_to_create_session",
        AuthError::OAuthUnableToLinkAccount => "unable_to_link_account",
        AuthError::LinkingNotAllowed => "unable_to_link_account",
        AuthError::LinkingDifferentEmailsNotAllowed => "email_does_not_match",
        AuthError::SocialAccountAlreadyLinked => "account_already_linked_to_different_user",
        AuthError::EmailNotVerified => "email_not_verified",
        AuthError::OAuthInvalidToken | AuthError::OAuthUserInfoUnavailable => {
            "unable_to_get_user_info"
        }
        _ => "internal_server_error",
    }
}

pub(crate) fn redirect_error(base: &str, error: &str, description: Option<&str>) -> Response {
    let mut suffix = url::form_urlencoded::Serializer::new(String::new());
    suffix.append_pair("error", error);
    if let Some(description) = description {
        suffix.append_pair("error_description", description);
    }
    let separator = if base.contains('?') { '&' } else { '?' };
    redirect(&format!("{base}{separator}{}", suffix.finish()))
}

pub(crate) fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => super::api_redirect(location),
        Err(_) => auth_error(AuthError::InvalidCallbackUrl),
    }
}

fn clear_state_cookie(service: &AuthService, response: Response) -> Response {
    with_cookie(
        response,
        serialize_cookie(
            &service.plugin_cookie(service.oauth_state_cookie_name()),
            "",
            Some(0),
        ),
    )
}
