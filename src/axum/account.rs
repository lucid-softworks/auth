use super::http::{
    PeerAddress, auth_error, clear_session_cookie, client_ip, current_session, user_agent,
    with_session_cookie,
};
use crate::{AuthError, AuthService, UserProfileUpdate};
use axum::{
    Extension, Json, Router,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::sync::Arc;

use crate::protocol::better_auth::{
    ChangeEmailRequest, ChangePasswordRequest, ChangePasswordResponse, RevokeSessionRequest,
    StatusResponse, UpdateSessionResponse, UpdateUserRequest,
};

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/update-user", post(update_user))
        .route("/update-session", post(update_session))
        .route("/change-email", post(change_email))
        .route("/change-password", post(change_password))
        .route("/list-sessions", get(list_sessions))
        .route("/revoke-session", post(revoke_session))
        .route("/revoke-other-sessions", post(revoke_other_sessions))
        .route("/revoke-sessions", post(revoke_sessions))
}

async fn change_email(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<ChangeEmailRequest>,
) -> Response {
    let Some(current) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service
        .change_email(&current, &input.new_email, input.callback_url.as_deref())
        .await
    {
        Ok(updated) => {
            let body = Json(StatusResponse { status: true });
            match (updated, super::session_token(&service, &headers)) {
                (Some(_), Some(token)) => {
                    with_session_cookie(&service, &token, Some(true), body).await
                }
                _ => body.into_response(),
            }
        }
        Err(error) => change_email_error(error),
    }
}

async fn update_session(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<serde_json::Map<String, serde_json::Value>>,
) -> Response {
    let Some(current) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service.update_current_session(&current, input).await {
        Ok(session) => {
            let token = super::session_token(&service, &headers).unwrap_or_default();
            let body = Json(UpdateSessionResponse {
                session: service.better_auth_session(&session, token.clone()),
            });
            if token.is_empty() {
                body.into_response()
            } else {
                with_session_cookie(&service, &token, Some(true), body).await
            }
        }
        Err(error) => auth_error(error),
    }
}

async fn update_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UpdateUserRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    if input
        .email
        .as_ref()
        .is_some_and(crate::additional_fields::json_truthy)
    {
        return auth_error(AuthError::InvalidRequest("Email cannot be updated".into()));
    }
    match service
        .update_current_user(
            &session,
            UserProfileUpdate {
                name: input.name,
                image: input.image,
                username: input.username,
                display_username: input.display_username,
                additional_fields: input.additional_fields,
            },
        )
        .await
    {
        Ok(_) => {
            let response = Json(StatusResponse { status: true });
            match super::session_token(&service, &headers) {
                Some(token) => with_session_cookie(&service, &token, Some(true), response).await,
                None => response.into_response(),
            }
        }
        Err(error) => auth_error(error),
    }
}

fn change_email_error(error: AuthError) -> Response {
    let message = match error {
        AuthError::EmailIsSame => "Email is the same",
        AuthError::VerificationEmailNotEnabled => "Verification email isn't enabled",
        _ => return auth_error(error),
    };
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "message": message })),
    )
        .into_response()
}

async fn change_password(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    Json(input): Json<ChangePasswordRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .change_password(
            &session,
            input.current_password,
            input.new_password,
            input.revoke_other_sessions.unwrap_or(false),
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(changed) => {
            let user = match service.better_auth_user(&changed.user).await {
                Ok(user) => user,
                Err(error) => return auth_error(error),
            };
            if let Some(replacement) = changed.replacement_session {
                let token = replacement.token;
                with_session_cookie(
                    &service,
                    &token,
                    Some(true),
                    Json(ChangePasswordResponse {
                        token: Some(token.clone()),
                        user,
                    }),
                )
                .await
            } else {
                Json(ChangePasswordResponse { token: None, user }).into_response()
            }
        }
        Err(error) => auth_error(error),
    }
}

async fn list_sessions(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service.list_current_sessions(&session).await {
        Ok(sessions) => Json(
            sessions
                .iter()
                .map(|session| service.better_auth_session(session, session.token.clone()))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn revoke_session(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<RevokeSessionRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .revoke_current_user_session_token(&session, &input.token)
        .await
    {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn revoke_other_sessions(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service.revoke_other_sessions(&session).await {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn revoke_sessions(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service.revoke_all_current_user_sessions(&session).await {
        Ok(()) => clear_session_cookie(&service, Json(StatusResponse { status: true })),
        Err(error) => auth_error(error),
    }
}
