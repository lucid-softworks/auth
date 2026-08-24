use super::MultiSessionConfig;
use crate::{
    AuthError, AuthService, AxumPluginRoute,
    axum::{
        body::BetterAuthBody,
        http::{
            auth_error, clear_session_cookie_from_request, dont_remember, serialize_cookie,
            with_bound_session_cookie, with_cookie,
        },
    },
    cookie::ResolvedCookie,
    protocol::better_auth::SessionResponse,
};
use axum::{
    Extension, Json,
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    config: Arc<MultiSessionConfig>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/multi-session/list-device-sessions",
            get(list_device_sessions).layer(Extension(config.clone())),
        ),
        AxumPluginRoute::new(
            "/multi-session/set-active",
            post(set_active).layer(Extension(config.clone())),
        ),
        AxumPluginRoute::new(
            "/multi-session/revoke",
            post(revoke).layer(Extension(config)),
        ),
    ]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionTokenBody {
    session_token: String,
}

#[derive(Serialize)]
struct StatusResponse {
    status: bool,
}

async fn list_device_sessions(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let tokens = verified_multi_session_tokens(&service, &headers);
    if tokens.is_empty() {
        return Json(Vec::<SessionResponse>::new()).into_response();
    }
    let sessions = match service.multi_session_list(&tokens, true).await {
        Ok(sessions) => sessions,
        Err(error) => return auth_error(error),
    };
    let mut unique = Vec::new();
    for session in sessions {
        if unique
            .iter()
            .any(|existing: &crate::SessionWithUser| existing.user.id == session.user.id)
        {
            continue;
        }
        unique.push(session);
    }
    let mut output = Vec::with_capacity(unique.len());
    for session in unique {
        match service
            .better_auth_session_response(&session, session.session.token.clone())
            .await
        {
            Ok(session) => output.push(session),
            Err(error) => return auth_error(error),
        }
    }
    Json(output).into_response()
}

async fn set_active(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<SessionTokenBody>,
) -> Response {
    let cookie_name = selector_cookie_name(&service, &input.session_token);
    let Some(token) = verified_cookie(&service, &headers, &cookie_name) else {
        return auth_error(AuthError::MultiSessionInvalidToken);
    };
    let session = match service.multi_session_stored(&token).await {
        Ok(Some(session)) if session.session.expires_at >= Utc::now() => session,
        Ok(_) => {
            return with_cookie(
                auth_error(AuthError::MultiSessionInvalidToken),
                serialize_cookie(&named_session_cookie(&service, cookie_name), "", Some(0)),
            );
        }
        Err(error) => return auth_error(error),
    };
    let response = match service
        .better_auth_session_response(&session, token.clone())
        .await
    {
        Ok(response) => response,
        Err(error) => return auth_error(error),
    };
    let remember_me = Some(!dont_remember(&service, &headers));
    with_bound_session_cookie(
        &service,
        &headers,
        session.user.id,
        &token,
        remember_me,
        Json(response),
    )
    .await
}

async fn revoke(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<SessionTokenBody>,
) -> Response {
    let Some(current) = crate::axum::http::current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let cookie_name = selector_cookie_name(&service, &input.session_token);
    let Some(token) = verified_cookie(&service, &headers, &cookie_name) else {
        return auth_error(AuthError::MultiSessionInvalidToken);
    };
    if let Err(error) = service.multi_session_delete(&token).await {
        return auth_error(error);
    }
    let response = with_cookie(
        Json(StatusResponse { status: true }),
        serialize_cookie(&named_session_cookie(&service, cookie_name), "", Some(0)),
    );
    if current.session.token != token {
        return response;
    }
    let remaining = verified_multi_session_tokens(&service, &headers);
    let replacement = match service.multi_session_list(&remaining, true).await {
        Ok(sessions) => sessions.into_iter().next(),
        Err(error) => return auth_error(error),
    };
    match replacement {
        Some(session) => {
            let token = session.session.token.clone();
            let remember_me = Some(!dont_remember(&service, &headers));
            with_bound_session_cookie(
                &service,
                &headers,
                session.user.id,
                &token,
                remember_me,
                response,
            )
            .await
        }
        None => clear_session_cookie_from_request(&service, &headers, response),
    }
}

pub(crate) async fn attach_new_session_cookie(
    service: &AuthService,
    headers: &HeaderMap,
    user_id: uuid::Uuid,
    token: &str,
    mut response: Response,
) -> Response {
    let Some(config) = service.multi_session_config() else {
        return response;
    };
    if response.headers().get(header::SET_COOKIE).is_none() {
        return response;
    }
    let cookie_name = selector_cookie_name(service, token);
    let cookies = parsed_cookies(headers);
    if cookies.iter().any(|(name, _)| name == &cookie_name)
        || response_cookie_names(&response).any(|name| name == cookie_name)
    {
        return response;
    }
    let multi_session_keys: Vec<_> = cookies
        .iter()
        .filter(|(name, _)| is_multi_session_cookie(name))
        .map(|(name, _)| name.clone())
        .collect();
    let mut tokens_to_delete = Vec::new();
    for key in &multi_session_keys {
        let Some(existing_token) = verified_cookie(service, headers, key) else {
            continue;
        };
        let existing = match service.multi_session_stored(&existing_token).await {
            Ok(existing) => existing,
            Err(error) => return auth_error(error),
        };
        if existing.is_some_and(|session| session.user.id == user_id) {
            tokens_to_delete.push(existing_token);
            response = with_cookie(
                response,
                serialize_cookie(&named_session_cookie(service, key.clone()), "", Some(0)),
            );
        }
    }
    for token in &tokens_to_delete {
        if let Err(error) = service.multi_session_delete(token).await {
            return auth_error(error);
        }
    }
    let main_cookie_was_set = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.contains(&service.session_cookie().name));
    let count =
        (multi_session_keys.len() - tokens_to_delete.len()) as f64 + f64::from(main_cookie_was_set);
    if count > config.maximum_sessions {
        return response;
    }
    with_cookie(
        response,
        serialize_cookie(
            &named_session_cookie(service, cookie_name),
            &service.signed_cookie_value(token),
            Some(service.session_ttl().num_seconds()),
        ),
    )
}

pub(crate) async fn cleanup_sign_out(
    service: &AuthService,
    headers: &HeaderMap,
    mut response: Response,
) -> Response {
    if service.multi_session_config().is_none() {
        return response;
    }
    let cookies = parsed_cookies(headers);
    let mut verified_tokens = Vec::new();
    for (name, _) in cookies
        .iter()
        .filter(|(name, _)| is_multi_session_cookie(name))
    {
        let Some(token) = verified_cookie(service, headers, name) else {
            continue;
        };
        let expired_name = canonical_sign_out_cookie_name(name);
        response = with_cookie(
            response,
            serialize_cookie(&named_session_cookie(service, expired_name), "", Some(0)),
        );
        verified_tokens.push(token);
    }
    for token in verified_tokens {
        if let Err(error) = service.multi_session_delete(&token).await {
            return auth_error(error);
        }
    }
    response
}

fn selector_cookie_name(service: &AuthService, token: &str) -> String {
    format!(
        "{}_multi-{}",
        service.session_cookie().name,
        token.to_lowercase()
    )
}

fn named_session_cookie(service: &AuthService, name: String) -> ResolvedCookie {
    let mut cookie = service.session_cookie();
    cookie.name = name;
    cookie
}

fn is_multi_session_cookie(name: &str) -> bool {
    name.contains("_multi-")
}

fn verified_multi_session_tokens(service: &AuthService, headers: &HeaderMap) -> Vec<String> {
    parsed_cookies(headers)
        .into_iter()
        .filter(|(name, _)| is_multi_session_cookie(name))
        .filter_map(|(name, _)| verified_cookie(service, headers, &name))
        .collect()
}

fn verified_cookie(service: &AuthService, headers: &HeaderMap, name: &str) -> Option<String> {
    service.verify_cookie_value(raw_cookie_value_first(headers, name)?)
}

fn raw_cookie_value_first<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let header = headers.get(header::COOKIE)?.to_str().ok()?;
    for chunk in header.split(';') {
        let Some((raw_name, raw_value)) = chunk.split_once('=') else {
            continue;
        };
        let candidate = trim_ows(raw_name);
        let value = trim_ows(raw_value);
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value);
        if candidate == name && valid_cookie_name(candidate) && valid_cookie_value(value) {
            return Some(value);
        }
    }
    None
}

fn response_cookie_names(response: &Response) -> impl Iterator<Item = String> + '_ {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split_once('=').map(|(name, _)| name.to_owned()))
}

fn parsed_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    let Some(header) = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
    else {
        return Vec::new();
    };
    let mut cookies = Vec::new();
    for chunk in header.split(';') {
        let Some((raw_name, raw_value)) = chunk.split_once('=') else {
            continue;
        };
        let name = trim_ows(raw_name);
        let value = trim_ows(raw_value);
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value);
        if !valid_cookie_name(name) || !valid_cookie_value(value) {
            continue;
        }
        let value = value.to_owned();
        if let Some((_, existing)) = cookies.iter_mut().find(|(candidate, _)| candidate == name) {
            *existing = value;
        } else {
            cookies.push((name.to_owned(), value));
        }
    }
    cookies
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn valid_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                0x21 | 0x23..=0x27 | 0x2A | 0x2B | 0x2D | 0x2E | 0x30..=0x39
                    | 0x41..=0x5A | 0x5E | 0x5F | 0x60 | 0x61..=0x7A | 0x7C | 0x7E
            )
        })
}

fn valid_cookie_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, 0x20 | 0x21 | 0x23..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E))
}

fn canonical_sign_out_cookie_name(name: &str) -> String {
    name.to_lowercase().replacen("__secure-", "__Secure-", 1)
}
