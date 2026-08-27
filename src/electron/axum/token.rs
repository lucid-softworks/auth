use super::input::{TokenBody, nonempty_body_error};
use crate::{
    AuthService,
    axum::{body::BetterAuthBody, http::with_bound_session_cookie},
};
use axum::{
    Extension, Json,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    user: crate::protocol::better_auth::BetterAuthUser,
}

pub(super) async fn exchange(
    Extension(service): Extension<Arc<AuthService>>,
    _options: Extension<Arc<super::ElectronOptions>>,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<TokenBody>,
) -> Response {
    for (name, value) in [
        ("token", input.token.as_str()),
        ("state", input.state.as_str()),
        ("code_verifier", input.code_verifier.as_str()),
    ] {
        if value.is_empty() {
            return nonempty_body_error(name);
        }
    }
    let result = match crate::electron::transfer::exchange(
        &service,
        &input.token,
        &input.state,
        &input.code_verifier,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => return exchange_error(error),
    };
    let user = match service.better_auth_user(&result.session.user).await {
        Ok(user) => user,
        Err(_) => return internal("FAILED_TO_CREATE_SESSION", "Failed to create session"),
    };
    let response = Json(TokenResponse {
        token: result.token.clone(),
        user,
    });
    with_bound_session_cookie(
        &service,
        &headers,
        &result.session.user.id,
        &result.token,
        Some(true),
        response,
    )
    .await
}

fn exchange_error(error: crate::electron::transfer::ExchangeError) -> Response {
    use crate::electron::transfer::ExchangeError;
    match error {
        ExchangeError::InvalidToken => crate::axum::api_error(
            StatusCode::NOT_FOUND,
            "INVALID_TOKEN",
            "Invalid or expired token.",
        ),
        ExchangeError::MalformedToken => internal("INVALID_TOKEN", "Invalid or expired token."),
        ExchangeError::StateMismatch => bad_request("STATE_MISMATCH", "state mismatch"),
        ExchangeError::MissingCodeChallenge => {
            bad_request("MISSING_CODE_CHALLENGE", "missing code challenge")
        }
        ExchangeError::InvalidCodeVerifier => {
            bad_request("INVALID_CODE_VERIFIER", "Invalid code verifier")
        }
        ExchangeError::UserNotFound => internal("USER_NOT_FOUND", "User not found"),
        ExchangeError::FailedToCreateSession => {
            internal("FAILED_TO_CREATE_SESSION", "Failed to create session")
        }
    }
}

fn bad_request(code: &'static str, message: &'static str) -> Response {
    crate::axum::api_error(StatusCode::BAD_REQUEST, code, message)
}

fn internal(code: &'static str, message: &'static str) -> Response {
    crate::axum::api_error(StatusCode::INTERNAL_SERVER_ERROR, code, message)
}
