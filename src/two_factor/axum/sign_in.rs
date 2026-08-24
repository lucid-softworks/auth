use super::{expire_plugin_cookie, set_plugin_cookie};
use crate::{
    AuthService, SessionWithUser,
    axum::http::{
        auth_error, clear_session_cookie_from_request, signed_cookie_token,
        with_bound_session_cookie,
    },
    service::TwoFactorSignInOutcome,
};
use axum::{
    Json,
    http::{HeaderMap, HeaderValue, header},
    response::Response,
};
use serde::Serialize;

pub(crate) async fn finish_password_sign_in(
    service: &AuthService,
    headers: &HeaderMap,
    result: crate::SignInResult,
    remember_me: Option<bool>,
    callback_url: Option<String>,
    anonymous: Option<SessionWithUser>,
) -> Response {
    let trust_cookie = service.plugin_cookie("trust_device");
    let trust_value = signed_cookie_token(service, headers, &trust_cookie.name);
    match service
        .begin_two_factor_sign_in(result, remember_me, trust_value.as_deref())
        .await
    {
        Ok(TwoFactorSignInOutcome::Continue {
            result,
            rotated_trust_cookie,
        }) => {
            continue_sign_in(
                service,
                headers,
                *result,
                remember_me,
                callback_url,
                anonymous.as_ref(),
                rotated_trust_cookie,
            )
            .await
        }
        Ok(TwoFactorSignInOutcome::Challenge {
            identifier,
            methods,
            max_age_seconds,
        }) => challenge(
            service,
            headers,
            identifier,
            methods,
            max_age_seconds,
            trust_value.is_some(),
        ),
        Err(error) => auth_error(error),
    }
}

async fn continue_sign_in(
    service: &AuthService,
    headers: &HeaderMap,
    result: crate::SignInResult,
    remember_me: Option<bool>,
    callback_url: Option<String>,
    anonymous: Option<&SessionWithUser>,
    rotated_trust_cookie: Option<String>,
) -> Response {
    if let Some(source) = anonymous
        && let Err(error) = service.complete_anonymous_upgrade(source, &result).await
    {
        return auth_error(error);
    }
    let token = result.token.clone();
    let user_id = result.session.user.id;
    let body = match crate::axum::sign_in_response(service, result, callback_url.clone()).await {
        Ok(body) => body,
        Err(error) => return auth_error(error),
    };
    let mut response =
        with_bound_session_cookie(service, headers, user_id, &token, remember_me, Json(body)).await;
    if let Some(rotated) = rotated_trust_cookie {
        let max_age = service
            .two_factor_plugin()
            .expect("validated plugin")
            .config
            .trust_device_ttl
            .num_seconds();
        response = set_plugin_cookie(service, "trust_device", &rotated, max_age, response);
    }
    if let Some(callback_url) = callback_url
        && let Ok(location) = HeaderValue::from_str(&callback_url)
    {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

fn challenge(
    service: &AuthService,
    headers: &HeaderMap,
    identifier: String,
    methods: Vec<String>,
    max_age_seconds: i64,
    expire_trust: bool,
) -> Response {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ChallengeResponse {
        two_factor_redirect: bool,
        two_factor_methods: Vec<String>,
    }
    let response = clear_session_cookie_from_request(
        service,
        headers,
        Json(ChallengeResponse {
            two_factor_redirect: true,
            two_factor_methods: methods,
        }),
    );
    let response = set_plugin_cookie(
        service,
        "two_factor",
        &identifier,
        max_age_seconds,
        response,
    );
    if expire_trust {
        expire_plugin_cookie(service, "trust_device", response)
    } else {
        response
    }
}
