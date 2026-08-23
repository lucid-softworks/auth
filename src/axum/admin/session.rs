use super::{UserRequest, parse_uuid, success_response};
use crate::{
    AuthError, AuthService,
    axum::http::{
        PeerAddress, auth_error, client_ip, current_session, user_agent, with_session_cookie,
    },
    protocol::better_auth::{BetterAuthSession, SessionResponse},
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
        .route(
            "/api/auth/admin/list-user-sessions",
            post(list_user_sessions),
        )
        .route(
            "/api/auth/admin/revoke-user-session",
            post(revoke_user_session),
        )
        .route(
            "/api/auth/admin/revoke-user-sessions",
            post(revoke_user_sessions),
        )
        .route("/api/auth/admin/impersonate-user", post(impersonate_user))
        .route(
            "/api/auth/admin/stop-impersonating",
            post(stop_impersonating),
        )
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
            let response = SessionResponse::new(&result.session, result.token.clone());
            with_session_cookie(&service, &result.token, Some(true), Json(response))
        }
        Err(error) => auth_error(error),
    }
}

async fn stop_impersonating(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .stop_impersonating(
            &session,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => {
            let response = SessionResponse::new(&result.session, result.token.clone());
            with_session_cookie(&service, &result.token, Some(true), Json(response))
        }
        Err(error) => auth_error(error),
    }
}
