use super::http::{auth_error, current_session};
use crate::{
    AuthError, AuthService,
    protocol::better_auth::{BetterAuthUser, SuccessResponse},
};
use axum::{
    Extension, Json, Router,
    extract::{Query, RawQuery},
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

mod input;
mod session;

use input::*;

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/admin/list-users", get(list_users))
        .route("/admin/get-user", get(get_user))
        .route("/admin/create-user", post(create_user))
        .route("/admin/update-user", post(update_user))
        .route("/admin/has-permission", post(has_permission))
        .route("/admin/set-user-password", post(set_user_password))
        .route("/admin/remove-user", post(remove_user))
        .route("/admin/set-role", post(set_role))
        .route("/admin/ban-user", post(ban_user))
        .route("/admin/unban-user", post(unban_user))
        .merge(session::router())
}

#[derive(Serialize)]
struct PermissionResponse {
    error: Option<&'static str>,
    success: bool,
}

#[derive(Serialize)]
struct UserResponse {
    user: BetterAuthUser,
}

#[derive(Serialize)]
struct UsersResponse {
    users: Vec<BetterAuthUser>,
    total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<usize>,
}

async fn list_users(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<ListUsersQuery>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let response_limit = query.limit.filter(|limit| *limit != 0);
    let response_offset = query.offset.filter(|offset| *offset != 0);
    let limit = response_limit.unwrap_or(100);
    let offset = response_offset.unwrap_or(0);
    let filter_values = repeated_filter_values(raw_query.as_deref());
    let query = match admin_list_query(query, limit, offset, filter_values) {
        Ok(query) => query,
        Err(error) => return auth_error(error),
    };
    match service.list_users(&actor, query).await {
        Ok((users, total)) => {
            let mut output = Vec::with_capacity(users.len());
            for user in &users {
                match service.better_auth_user(user).await {
                    Ok(user) => output.push(user),
                    Err(error) => return auth_error(error),
                }
            }
            Json(UsersResponse {
                users: output,
                total,
                limit: response_limit,
                offset: response_offset,
            })
            .into_response()
        }
        Err(AuthError::Storage(_)) => Json(UsersResponse {
            users: Vec::new(),
            total: 0,
            limit: None,
            offset: None,
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn get_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(input): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = async {
        let id = input
            .get("id")
            .ok_or_else(|| AuthError::InvalidRequest("id is required".into()))?;
        service.admin_get_user(&actor, parse_uuid(id)?).await
    }
    .await;
    raw_user_response(&service, result).await
}

async fn create_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<CreateUserRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = async {
        let input = input.into_admin_input()?;
        service.create_admin_user(&actor, input).await
    }
    .await;
    user_response(&service, result).await
}

async fn update_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UpdateUserRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = async {
        let user_id = parse_uuid(&input.user_id)?;
        let update = parse_user_update(input.data)?;
        service.admin_update_user(&actor, user_id, update).await
    }
    .await;
    raw_user_response(&service, result).await
}

async fn has_permission(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<HasPermissionRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    if input.permissions.is_none() {
        let _ = input.permission;
        return auth_error(AuthError::InvalidRequest(
            "invalid permission check. no permission(s) were passed".into(),
        ));
    }
    let user_id = match input.user_id.as_deref().map(parse_uuid).transpose() {
        Ok(user_id) => user_id,
        Err(error) => return auth_error(error),
    };
    match service
        .admin_has_permission(
            &actor,
            user_id,
            input.role.as_deref(),
            input.permissions.as_ref().expect("checked above"),
        )
        .await
    {
        Ok(success) => Json(PermissionResponse {
            error: None,
            success,
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
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
        let role = input.role.stored();
        service.set_user_role(&actor, user_id, &role).await
    }
    .await;
    user_response(&service, result).await
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
    user_response(&service, result).await
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
    user_response(&service, result).await
}

fn parse_uuid(value: &str) -> Result<Uuid, AuthError> {
    Uuid::parse_str(value).map_err(|_| AuthError::InvalidRequest("invalid identifier".into()))
}

async fn user_response(
    service: &AuthService,
    result: Result<crate::AuthUser, AuthError>,
) -> Response {
    match result {
        Ok(user) => match service.better_auth_user(&user).await {
            Ok(user) => Json(UserResponse { user }).into_response(),
            Err(error) => auth_error(error),
        },
        Err(error) => auth_error(error),
    }
}

async fn raw_user_response(
    service: &AuthService,
    result: Result<crate::AuthUser, AuthError>,
) -> Response {
    match result {
        Ok(user) => match service.better_auth_user(&user).await {
            Ok(user) => Json(user).into_response(),
            Err(error) => auth_error(error),
        },
        Err(error) => auth_error(error),
    }
}

fn success_response(result: Result<(), AuthError>) -> Response {
    match result {
        Ok(()) => Json(SuccessResponse { success: true }).into_response(),
        Err(error) => auth_error(error),
    }
}
