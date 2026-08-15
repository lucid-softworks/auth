use super::http::{auth_error, current_session, user_agent, with_session_cookie};
use crate::{
    AuthError, AuthService,
    protocol::better_auth::{BetterAuthSession, BetterAuthUser, SessionResponse, SuccessResponse},
};
use axum::{
    Extension, Json, Router,
    extract::Query,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/api/auth/admin/list-users", get(list_users))
        .route("/api/auth/admin/set-role", post(set_role))
        .route("/api/auth/admin/ban-user", post(ban_user))
        .route("/api/auth/admin/unban-user", post(unban_user))
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

#[derive(Debug, Default, Deserialize)]
struct ListUsersQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    fn one(self) -> Result<String, AuthError> {
        match self {
            Self::One(role) => Ok(role),
            Self::Many(mut roles) if roles.len() == 1 => roles
                .pop()
                .ok_or_else(|| AuthError::InvalidRequest("role is required".into())),
            Self::Many(_) => Err(AuthError::InvalidRequest(
                "this server assigns one role per user".into(),
            )),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetRoleRequest {
    user_id: String,
    role: RoleInput,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserRequest {
    user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BanUserRequest {
    user_id: String,
    ban_reason: Option<String>,
    ban_expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeSessionRequest {
    session_token: String,
}

#[derive(Serialize)]
struct UserResponse {
    user: BetterAuthUser,
}

#[derive(Serialize)]
struct UsersResponse {
    users: Vec<BetterAuthUser>,
    total: i64,
    limit: usize,
    offset: usize,
}

#[derive(Serialize)]
struct SessionsResponse {
    sessions: Vec<BetterAuthSession>,
}

async fn list_users(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<ListUsersQuery>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let limit = query.limit.unwrap_or(100).clamp(1, 100);
    let offset = query.offset.unwrap_or(0);
    match service.list_users(&actor, limit, offset).await {
        Ok((users, total)) => Json(UsersResponse {
            users: users.iter().map(BetterAuthUser::from).collect(),
            total,
            limit,
            offset,
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn set_role(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<SetRoleRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = async {
        let user_id = parse_uuid(&input.user_id)?;
        let role = input.role.one()?;
        service.set_user_role(&actor, user_id, &role).await
    }
    .await;
    user_response(result)
}

async fn ban_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<BanUserRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = async {
        let user_id = parse_uuid(&input.user_id)?;
        let expires_at = input
            .ban_expires_in
            .map(|seconds| {
                if seconds <= 0 {
                    Err(AuthError::InvalidRequest(
                        "banExpiresIn must be positive".into(),
                    ))
                } else {
                    Ok(Utc::now() + Duration::seconds(seconds.min(31_536_000)))
                }
            })
            .transpose()?;
        service
            .ban_user(&actor, user_id, input.ban_reason, expires_at)
            .await
    }
    .await;
    user_response(result)
}

async fn unban_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UserRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = match parse_uuid(&input.user_id) {
        Ok(user_id) => service.unban_user(&actor, user_id).await,
        Err(error) => Err(error),
    };
    user_response(result)
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
    headers: HeaderMap,
    Json(input): Json<UserRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = match parse_uuid(&input.user_id) {
        Ok(user_id) => {
            service
                .impersonate_user(&actor, user_id, None, user_agent(&headers))
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
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .stop_impersonating(&session, None, user_agent(&headers))
        .await
    {
        Ok(result) => {
            let response = SessionResponse::new(&result.session, result.token.clone());
            with_session_cookie(&service, &result.token, Some(true), Json(response))
        }
        Err(error) => auth_error(error),
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, AuthError> {
    Uuid::parse_str(value).map_err(|_| AuthError::InvalidRequest("invalid identifier".into()))
}

fn user_response(result: Result<crate::AuthUser, AuthError>) -> Response {
    match result {
        Ok(user) => Json(UserResponse {
            user: BetterAuthUser::from(&user),
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

fn success_response(result: Result<(), AuthError>) -> Response {
    match result {
        Ok(()) => Json(SuccessResponse { success: true }).into_response(),
        Err(error) => auth_error(error),
    }
}
