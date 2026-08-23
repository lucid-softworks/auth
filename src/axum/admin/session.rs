use super::{UserRequest, parse_uuid, success_response};
use crate::{
    AuthError, AuthService,
    axum::http::{
        PeerAddress, auth_error, client_ip, current_session, serialize_cookie, signed_cookie_token,
        user_agent, with_cookie, with_session_cookie,
    },
    protocol::better_auth::BetterAuthSession,
};
use axum::{
    Extension, Json, Router,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/admin/list-user-sessions", post(list_user_sessions))
        .route("/admin/revoke-user-session", post(revoke_user_session))
        .route("/admin/revoke-user-sessions", post(revoke_user_sessions))
        .route("/admin/impersonate-user", post(impersonate_user))
        .route("/admin/stop-impersonating", post(stop_impersonating))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeSessionRequest {
    session_token: String,
}

#[derive(Serialize)]
struct SessionsResponse {
    sessions: Vec<BetterAuthSession>,
}

async fn list_user_sessions(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UserRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = async {
        let user_id = parse_uuid(&input.user_id)?;
        service.list_user_sessions(&actor, user_id).await
    }
    .await;
    match result {
        Ok(sessions) => Json(SessionsResponse {
            sessions: sessions
                .iter()
                .map(|session| BetterAuthSession::from_session(session, session.id.to_string()))
                .collect(),
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn revoke_user_session(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<RevokeSessionRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = match parse_uuid(&input.session_token) {
        Ok(session_id) => service.revoke_user_session(&actor, session_id).await,
        Err(error) => Err(error),
    };
    success_response(result)
}

async fn revoke_user_sessions(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UserRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = match parse_uuid(&input.user_id) {
        Ok(user_id) => service.revoke_user_sessions(&actor, user_id).await,
        Err(error) => Err(error),
    };
    success_response(result)
}

async fn impersonate_user(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    Json(input): Json<UserRequest>,
) -> Response {
    let Some(actor_token) = crate::axum::http::session_token(&service, &headers) else {
        return auth_error(AuthError::InvalidSession);
    };
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = match parse_uuid(&input.user_id) {
        Ok(user_id) => {
            service
                .impersonate_user(
                    &actor,
                    user_id,
                    client_ip(&service, &headers, peer),
                    user_agent(&headers),
                )
                .await
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(result) => {
            match service
                .better_auth_session_response(&result.session, result.token.clone())
                .await
            {
                Ok(response) => {
                    let response =
                        with_session_cookie(&service, &result.token, Some(true), Json(response));
                    with_admin_session_cookie(&service, &actor_token, response)
                }
                Err(error) => auth_error(error),
            }
        }
        Err(error) => auth_error(error),
    }
}

async fn stop_impersonating(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let cookie = service.plugin_cookie("admin_session");
    let Some(actor_token) = signed_cookie_token(&service, &headers, &cookie.name) else {
        return auth_error(AuthError::InvalidSession);
    };
    match service.stop_impersonating(&session, &actor_token).await {
        Ok(result) => {
            match service
                .better_auth_session_response(&result.session, result.token.clone())
                .await
            {
                Ok(response) => {
                    let response =
                        with_session_cookie(&service, &result.token, Some(true), Json(response));
                    clear_admin_session_cookie(&service, response)
                }
                Err(error) => auth_error(error),
            }
        }
        Err(error) => auth_error(error),
    }
}

fn with_admin_session_cookie(
    service: &AuthService,
    token: &str,
    body: impl IntoResponse,
) -> Response {
    let cookie = service.plugin_cookie("admin_session");
    with_cookie(
        body,
        serialize_cookie(
            &cookie,
            &service.signed_cookie_value(token),
            Some(service.session_ttl().num_seconds()),
        ),
    )
}

fn clear_admin_session_cookie(service: &AuthService, body: impl IntoResponse) -> Response {
    let cookie = service.plugin_cookie("admin_session");
    with_cookie(body, serialize_cookie(&cookie, "", Some(0)))
}
