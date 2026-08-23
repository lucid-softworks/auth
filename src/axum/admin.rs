use super::http::{auth_error, current_session};
use crate::{
    AuthError, AuthService, NewPasswordUser,
    protocol::better_auth::{BetterAuthUser, SuccessResponse},
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
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

mod session;

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/admin/list-users", get(list_users))
        .route("/admin/create-user", post(create_user))
        .route("/admin/set-user-password", post(set_user_password))
        .route("/admin/remove-user", post(remove_user))
        .route("/admin/set-role", post(set_role))
        .route("/admin/ban-user", post(ban_user))
        .route("/admin/unban-user", post(unban_user))
        .merge(session::router())
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
struct CreateUserRequest {
    email: String,
    password: Option<String>,
    name: String,
    role: Option<RoleInput>,
    data: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetUserPasswordRequest {
    user_id: String,
    new_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BanUserRequest {
    user_id: String,
    ban_reason: Option<String>,
    ban_expires_in: Option<i64>,
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

async fn create_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(mut input): Json<CreateUserRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = async {
        let role = input
            .role
            .map(RoleInput::one)
            .transpose()?
            .unwrap_or_else(|| "viewer".into());
        let username = input
            .data
            .as_mut()
            .and_then(|data| data.remove("username"))
            .and_then(|value| value.as_str().map(str::to_owned))
            .or_else(|| {
                input
                    .email
                    .split_once('@')
                    .map(|(local, _)| local.to_owned())
            })
            .ok_or_else(|| AuthError::InvalidRequest("username is required".into()))?;
        let password = input
            .password
            .ok_or_else(|| AuthError::InvalidRequest("password is required".into()))?;
        service
            .create_user(
                &actor,
                NewPasswordUser {
                    username,
                    name: input.name,
                    email: Some(input.email),
                    password,
                    role,
                },
            )
            .await
    }
    .await;
    user_response(result)
}

async fn set_user_password(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<SetUserPasswordRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = match parse_uuid(&input.user_id) {
        Ok(user_id) => {
            service
                .set_user_password(&actor, user_id, input.new_password)
                .await
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => {
            Json(crate::protocol::better_auth::StatusResponse { status: true }).into_response()
        }
        Err(error) => auth_error(error),
    }
}

async fn remove_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UserRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = match parse_uuid(&input.user_id) {
        Ok(user_id) => service.remove_user(&actor, user_id).await,
        Err(error) => Err(error),
    };
    success_response(result)
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
