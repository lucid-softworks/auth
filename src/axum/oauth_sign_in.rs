use super::{
    body::BetterAuthBody,
    http::{
        PeerAddress, auth_error, client_ip, current_session, serialize_cookie, user_agent,
        with_bound_session_cookie, with_cookie,
    },
    oauth::with_provider_account_cookie,
};
use crate::{AuthError, AuthService, SocialSignInInput, SocialSignInResult};
use axum::{
    Extension, Json,
    extract::OriginalUri,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
struct AuthorizationResponse {
    url: String,
    redirect: bool,
}

pub(super) async fn sign_in_social(
    Extension(service): Extension<Arc<AuthService>>,
    OriginalUri(uri): OriginalUri,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(mut input): BetterAuthBody<SocialSignInInput>,
) -> Response {
    let proxy =
        match super::oauth_proxy::prepare_social_sign_in(&service, &headers, &uri, &mut input) {
            Ok(proxy) => proxy,
            Err(error) => return auth_error(error),
        };
    let provider_id = input.provider.clone();
    let anonymous = current_session(&service, &headers)
        .await
        .filter(|session| session.user.is_anonymous);
    let mut result = match service
        .sign_in_social_with_source_and_redirect_uri(
            input,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
            anonymous,
            proxy.as_ref().map(|proxy| proxy.redirect_uri.clone()),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => return auth_error(error),
    };
    if proxy.is_some() {
        super::oauth_proxy::wrap_social_sign_in(&service, &mut result).await;
    }
    social_sign_in_response(&service, &headers, &provider_id, result).await
}

async fn social_sign_in_response(
    service: &AuthService,
    headers: &HeaderMap,
    provider_id: &str,
    result: SocialSignInResult,
) -> Response {
    match result {
        SocialSignInResult::Authorization {
            url,
            redirect,
            state_cookie_name,
            state_cookie_value,
            state_cookie_max_age,
            ..
        } => authorization_response(
            service,
            url,
            redirect,
            state_cookie_name,
            state_cookie_value,
            state_cookie_max_age,
        ),
        SocialSignInResult::Session(result) => {
            let user = match service.better_auth_user(&result.session.user).await {
                Ok(user) => user,
                Err(error) => return auth_error(error),
            };
            let response = with_bound_session_cookie(
                service,
                headers,
                result.session.user.id,
                &result.token,
                Some(true),
                Json(crate::protocol::better_auth::SignInResponse {
                    redirect: false,
                    token: result.token.clone(),
                    url: None,
                    user,
                }),
            )
            .await;
            with_provider_account_cookie(
                service,
                headers,
                result.session.user.id,
                provider_id,
                response,
            )
            .await
        }
        SocialSignInResult::Linked => auth_error(AuthError::InvalidRequest(
            "linked-account response is invalid for social sign-in".into(),
        )),
    }
}

fn authorization_response(
    service: &AuthService,
    url: String,
    redirect: bool,
    state_cookie_name: &str,
    state_cookie_value: String,
    state_cookie_max_age: i64,
) -> Response {
    let mut response = Json(AuthorizationResponse {
        url: url.clone(),
        redirect,
    })
    .into_response();
    if redirect && let Ok(location) = HeaderValue::from_str(&url) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    let cookie = service.plugin_cookie(state_cookie_name);
    with_cookie(
        response,
        serialize_cookie(&cookie, &state_cookie_value, Some(state_cookie_max_age)),
    )
}
