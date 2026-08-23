use super::http::{
    PeerAddress, auth_error, clear_session_cookie, client_ip, current_session, user_agent,
    with_session_cookie,
};
use crate::{AuthError, AuthService, UserProfileUpdate};
use axum::{
    Extension, Json, Router,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::sync::Arc;
use uuid::Uuid;

use crate::protocol::better_auth::{
    BetterAuthSession, ChangePasswordRequest, ChangePasswordResponse, GenerateBackupCodesRequest,
    GenerateBackupCodesResponse, RevokeSessionRequest, StatusResponse, UpdateUserRequest,
    VerifyBackupCodeRequest, VerifyBackupCodeResponse,
};

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/update-user", post(update_user))
        .route("/change-password", post(change_password))
        .route("/list-sessions", get(list_sessions))
        .route("/revoke-session", post(revoke_session))
        .route("/revoke-other-sessions", post(revoke_other_sessions))
        .route("/revoke-sessions", post(revoke_sessions))
        .route(
            "/two-factor/generate-backup-codes",
            post(generate_backup_codes),
        )
        .route("/two-factor/verify-backup-code", post(verify_backup_code))
}

async fn update_user(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UpdateUserRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    if input.email.is_some() {
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
            },
        )
        .await
    {
        Ok(()) => {
            let response = Json(StatusResponse { status: true });
            match super::session_token(&service, &headers) {
                Some(token) => with_session_cookie(&service, &token, Some(true), response),
                None => response.into_response(),
            }
        }
        Err(error) => auth_error(error),
    }
}

async fn generate_backup_codes(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<GenerateBackupCodesRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .generate_recovery_codes(&session, input.password)
        .await
    {
        Ok(backup_codes) => Json(GenerateBackupCodesResponse {
            status: true,
            backup_codes,
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn verify_backup_code(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    Json(input): Json<VerifyBackupCodeRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .verify_recovery_code(
            &session,
            &input.code,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => {
            let body = Json(VerifyBackupCodeResponse {
                token: result.token.clone(),
                user: service.better_auth_user(&result.session.user),
            });
            if input.disable_session == Some(true) {
                body.into_response()
            } else {
                with_session_cookie(&service, &result.token, Some(true), body)
            }
        }
        Err(error) => auth_error(error),
    }
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
            let user = service.better_auth_user(&changed.user);
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
                .map(|session| BetterAuthSession::from_session(session, session.id.to_string()))
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
    let Ok(session_id) = Uuid::parse_str(&input.token) else {
        return Json(StatusResponse { status: true }).into_response();
    };
    match service
        .revoke_current_user_session(&session, session_id)
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
