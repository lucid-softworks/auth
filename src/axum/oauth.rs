use super::{
    body::BetterAuthBody,
    http::{
        PeerAddress, auth_error, client_ip, current_session, serialize_cookie, signed_cookie_token,
        user_agent, with_cookie, with_session_cookie,
    },
};
use crate::{AuthError, AuthService, SocialSignInInput, SocialSignInResult};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
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
        .route("/sign-in/social", post(sign_in_social))
        .route(
            "/callback/{provider}",
            axum::routing::get(oauth_callback).post(oauth_callback_post),
        )
}

#[derive(Serialize)]
struct AuthorizationResponse {
    url: String,
    redirect: bool,
}

#[derive(Deserialize, Serialize, Default)]
struct OAuthCallbackQuery {
    code: Option<String>,
    error: Option<String>,
    device_id: Option<String>,
    error_description: Option<String>,
    state: Option<String>,
    user: Option<String>,
    iss: Option<String>,
}

async fn sign_in_social(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<SocialSignInInput>,
) -> Response {
    let anonymous = current_session(&service, &headers)
        .await
        .filter(|session| session.user.is_anonymous);
    match service
        .sign_in_social_with_source(
            input,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
            anonymous,
        )
        .await
    {
        Ok(SocialSignInResult::Authorization {
            url,
            redirect,
            state,
        }) => {
            let mut response = Json(AuthorizationResponse {
                url: url.clone(),
                redirect,
            })
            .into_response();
            if redirect && let Ok(location) = HeaderValue::from_str(&url) {
                response.headers_mut().insert(header::LOCATION, location);
            }
            let cookie = service.plugin_cookie("state");
            with_cookie(
                response,
                serialize_cookie(&cookie, &service.signed_cookie_value(&state), Some(300)),
            )
        }
        Ok(SocialSignInResult::Session(result)) => {
            let user = match service.better_auth_user(&result.session.user).await {
                Ok(user) => user,
                Err(error) => return auth_error(error),
            };
            with_session_cookie(
                &service,
                &result.token,
                Some(true),
                Json(crate::protocol::better_auth::SignInResponse {
                    redirect: false,
                    token: result.token.clone(),
                    url: None,
                    user,
                }),
            )
        }
        Ok(SocialSignInResult::Linked) => auth_error(AuthError::InvalidRequest(
            "linked-account response is invalid for social sign-in".into(),
        )),
        Err(error) => auth_error(error),
    }
}

async fn oauth_callback_post(
    Extension(service): Extension<Arc<AuthService>>,
    Path(provider): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
    BetterAuthBody(input): BetterAuthBody<OAuthCallbackQuery>,
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
    let Some(state_token) = query.state.as_deref() else {
        return redirect_error(&default_error_url, "state_not_found", None);
    };
    let state = match service.oauth_state(state_token).await {
        Ok(state) => state,
        Err(_) => return redirect_error(&default_error_url, "state_mismatch", None),
    };
    let error_url = state.error_url.clone().unwrap_or(default_error_url);
    let cookie = service.plugin_cookie("state");
    if signed_cookie_token(&service, &headers, &cookie.name).as_deref() != Some(state_token) {
        return clear_state_cookie(&service, redirect_error(&error_url, "state_mismatch", None));
    }
    if service.consume_oauth_state(state_token).await.is_err() {
        return clear_state_cookie(&service, redirect_error(&error_url, "state_mismatch", None));
    }
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
            let response = redirect(&result.redirect_url);
            let response = match result.session {
                Some(session) => {
                    with_session_cookie(&service, &session.token, Some(true), response)
                }
                None => response,
            };
            clear_state_cookie(&service, response)
        }
        Err(error) => clear_state_cookie(
            &service,
            redirect_error(&error_url, callback_error_code(&error), None),
        ),
    }
}

fn callback_error_code(error: &AuthError) -> &'static str {
    match error {
        AuthError::OAuthInvalidCode => "invalid_code",
        AuthError::OAuthProviderNotFound => "provider_not_found",
        AuthError::OAuthIssuerMismatch => "issuer_mismatch",
        AuthError::OAuthNonceBindingMissing => "nonce_binding_missing",
        AuthError::OAuthStateMismatch => "state_mismatch",
        AuthError::OAuthEmailNotFound => "email_not_found",
        AuthError::OAuthAccountNotLinked => "account_not_linked",
        AuthError::OAuthSignupDisabled => "signup_disabled",
        AuthError::EmailNotVerified => "email_not_verified",
        AuthError::OAuthInvalidToken | AuthError::OAuthUserInfoUnavailable => {
            "unable_to_get_user_info"
        }
        _ => "internal_server_error",
    }
}

fn redirect_error(base: &str, error: &str, description: Option<&str>) -> Response {
    let mut suffix = url::form_urlencoded::Serializer::new(String::new());
    suffix.append_pair("error", error);
    if let Some(description) = description {
        suffix.append_pair("error_description", description);
    }
    let separator = if base.contains('?') { '&' } else { '?' };
    redirect(&format!("{base}{separator}{}", suffix.finish()))
}

fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => auth_error(AuthError::InvalidCallbackUrl),
    }
}

fn clear_state_cookie(service: &AuthService, response: Response) -> Response {
    with_cookie(
        response,
        serialize_cookie(&service.plugin_cookie("state"), "", Some(0)),
    )
}
