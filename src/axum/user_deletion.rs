use super::http::{auth_error, clear_session_cookie_from_request, current_session};
use crate::{
    AuthError, AuthService, DeleteUserResult,
    protocol::better_auth::{DeleteUserCallbackQuery, DeleteUserRequest, DeleteUserResponse},
};
use axum::{
    Extension, Json, Router,
    extract::Query,
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::sync::Arc;

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/delete-user", post(delete_user))
        .route("/delete-user/callback", get(delete_user_callback))
}

async fn delete_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<DeleteUserRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .delete_current_user(
            &session,
            input.password,
            input.token.as_deref(),
            input.callback_url.as_deref(),
        )
        .await
    {
        Ok(DeleteUserResult::Deleted) => clear_session_cookie_from_request(
            &service,
            &headers,
            Json(DeleteUserResponse {
                success: true,
                message: "User deleted",
            }),
        ),
        Ok(DeleteUserResult::VerificationSent) => Json(DeleteUserResponse {
            success: true,
            message: "Verification email sent",
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn delete_user_callback(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<DeleteUserCallbackQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::DeleteUserInfoNotFound);
    };
    match service
        .delete_current_user_callback(&session, &query.token)
        .await
    {
        Ok(()) => {
            let response = match query.callback_url {
                Some(callback_url) => redirect(&callback_url),
                None => Json(DeleteUserResponse {
                    success: true,
                    message: "User deleted",
                })
                .into_response(),
            };
            clear_session_cookie_from_request(&service, &headers, response)
        }
        Err(error) => auth_error(error),
    }
}

fn redirect(callback_url: &str) -> Response {
    match HeaderValue::from_str(callback_url) {
        Ok(location) => super::api_redirect(location),
        Err(_) => auth_error(AuthError::InvalidCallbackUrl),
    }
}
