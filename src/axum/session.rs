use super::{
    error::dynamic_error,
    http::{
        auth_error, clear_session_cookie_from_request, dont_remember, refresh_account_cookie,
        serialize_cookie, session_data_cookie, session_token, with_chunked_session_data_cookie,
        with_cookie, with_session_cache_cookie, with_session_cookie,
    },
};
use crate::{AuthError, AuthService, SessionWithUser, protocol::better_auth::SessionResponse};
use axum::{
    Extension, Json,
    extract::Query,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GetSessionQuery {
    disable_cookie_cache: Option<bool>,
    disable_refresh: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeferredSessionResponse {
    session: crate::protocol::better_auth::BetterAuthSession,
    user: crate::protocol::better_auth::BetterAuthUser,
    needs_refresh: bool,
}

pub(super) async fn get_session(
    Extension(service): Extension<Arc<AuthService>>,
    method: Method,
    headers: HeaderMap,
    Query(query): Query<GetSessionQuery>,
) -> Response {
    if method == Method::POST && !service.defer_session_refresh() {
        return cache_headers(dynamic_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "METHOD_NOT_ALLOWED",
            "POST method requires deferSessionRefresh to be enabled in session config",
        ));
    }
    let token = session_token(&service, &headers);
    let non_persistent = dont_remember(&service, &headers);
    if let Some(response) = cached_session_response(
        &service,
        &headers,
        token.as_deref(),
        query.disable_cookie_cache == Some(true),
        non_persistent,
    ) {
        return response;
    }
    let response = match token {
        Some(token) => {
            stateful_session_response(&service, &headers, &token, &query, method, non_persistent)
                .await
        }
        None => fallback_session_response(&service, &headers).await,
    };
    cache_headers(response)
}

async fn stateful_session_response(
    service: &AuthService,
    headers: &HeaderMap,
    token: &str,
    query: &GetSessionQuery,
    method: Method,
    non_persistent: bool,
) -> Response {
    let delete_expired = !service.defer_session_refresh() || method == Method::POST;
    let session = match service.session_for_http(token, delete_expired).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return clear_session_cookie_from_request(
                service,
                headers,
                Json::<Option<SessionResponse>>(None),
            );
        }
        Err(error) => return auth_error(error),
    };
    let response = match session_response(service, &session, token).await {
        Ok(response) => response,
        Err(error) => return auth_error(error),
    };
    if non_persistent || query.disable_refresh == Some(true) {
        return refresh_account_cookie(service, headers, session.user.id, Json(Some(response)));
    }
    let needs_refresh = service.session_needs_refresh(&session, Utc::now());
    if service.defer_session_refresh() && method == Method::GET {
        let response = deferred_response(service, token, &session, response, needs_refresh).await;
        return refresh_account_cookie(service, headers, session.user.id, response);
    }
    if needs_refresh {
        return refreshed_response(service, headers, token, &session).await;
    }
    let response = with_session_cache_cookie(
        service,
        token,
        Some(&session),
        Some(true),
        Json(Some(response)),
    )
    .await;
    refresh_account_cookie(service, headers, session.user.id, response)
}

async fn deferred_response(
    service: &AuthService,
    token: &str,
    session: &SessionWithUser,
    response: SessionResponse,
    needs_refresh: bool,
) -> Response {
    let response = DeferredSessionResponse {
        session: response.session,
        user: response.user,
        needs_refresh,
    };
    with_session_cache_cookie(service, token, Some(session), Some(true), Json(response)).await
}

async fn refreshed_response(
    service: &AuthService,
    headers: &HeaderMap,
    token: &str,
    current: &SessionWithUser,
) -> Response {
    let refreshed = match service.refresh_http_session(current, Utc::now()).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return clear_session_cookie_from_request(
                service,
                headers,
                dynamic_error(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "Failed to get session",
                ),
            );
        }
        Err(error) => return auth_error(error),
    };
    let response = match session_response(service, &refreshed, token).await {
        Ok(response) => response,
        Err(error) => return auth_error(error),
    };
    let response = with_session_cookie(service, token, Some(true), Json(response)).await;
    refresh_account_cookie(service, headers, refreshed.user.id, response)
}

async fn session_response(
    service: &AuthService,
    session: &SessionWithUser,
    token: &str,
) -> Result<SessionResponse, AuthError> {
    Ok(SessionResponse {
        session: service.better_auth_session(&session.session, token),
        user: service.better_auth_user(&session.user).await?,
    })
}

async fn fallback_session_response(service: &AuthService, headers: &HeaderMap) -> Response {
    let session = match service.plugin_session(headers).await {
        Ok(Some(session)) => Some((session.session, session.token.to_owned())),
        Ok(None) => service
            .development_session()
            .map(|session| (session, "development-bypass".into())),
        Err(error) => return auth_error(error),
    };
    let Some((session, token)) = session else {
        return Json::<Option<SessionResponse>>(None).into_response();
    };
    match session_response(service, &session, &token).await {
        Ok(response) => Json(Some(response)).into_response(),
        Err(error) => auth_error(error),
    }
}

fn cached_session_response(
    service: &AuthService,
    headers: &HeaderMap,
    token: Option<&str>,
    disabled: bool,
    non_persistent: bool,
) -> Option<Response> {
    if disabled {
        return None;
    }
    let token = token?;
    let cache = session_data_cookie(service, headers)?;
    let (value, expires_at) = service.decode_session_cookie_cache(token, &cache)?;
    let user_id = value["user"]["id"]
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok());
    let mut response = Json(value).into_response();
    if service.should_refresh_cookie_cache(expires_at)
        && let Some(refreshed) = service.refresh_session_cookie_cache(&cache)
    {
        let cache_age = (!non_persistent).then(|| service.cookie_cache_max_age());
        response = with_chunked_session_data_cookie(service, &refreshed, cache_age, response);
        let token_age = (!non_persistent).then(|| service.session_ttl().num_seconds());
        response = with_cookie(
            response,
            serialize_cookie(
                &service.session_cookie(),
                &service.signed_cookie_value(token),
                token_age,
            ),
        );
    }
    if let Some(user_id) = user_id {
        response = refresh_account_cookie(service, headers, user_id, response);
    }
    Some(cache_headers(response))
}

fn cache_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
