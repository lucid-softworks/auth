use crate::{AuthError, protocol::better_auth::ErrorResponse};
use axum::{
    Json,
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

mod admin;
mod anonymous;
mod credential;
mod details;
mod have_i_been_pwned;
mod oauth;
mod plugin;

use details::{
    ErrorDetails, access_error_details, delete_user_error_details, is_delete_user_error,
    is_passkey_error, passkey_error_details, password_error_details,
    request_security_error_details,
};

#[derive(Debug, Clone)]
pub(crate) struct ApiErrorResponse {
    pub(crate) message: String,
}

pub(crate) fn auth_error(error: AuthError) -> Response {
    let message = error.to_string();
    marked(auth_error_inner(error), message)
}

/// Builds a Better Auth `APIError` response for a native plugin endpoint.
///
/// The internal marker lets compatible after hooks distinguish API errors
/// from arbitrary JSON responses with `code` and `message` fields.
pub fn api_error(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Response {
    let message = message.into();
    marked(
        (
            status,
            Json(OwnedErrorResponse {
                code: code.into(),
                message: message.clone(),
            }),
        )
            .into_response(),
        message,
    )
}

/// Builds a marked Better Auth `APIError` response with a caller-owned body.
///
/// This is useful for plugin errors that carry fields in addition to `code`
/// and `message`; compatible after hooks can recognize the response without
/// mistaking ordinary JSON for an API error.
pub fn api_error_with_body(status: StatusCode, body: serde_json::Value) -> Response {
    let message = body
        .get("message")
        .map(|value| match value {
            serde_json::Value::String(message) => message.clone(),
            value => value.to_string(),
        })
        .unwrap_or_else(|| status.to_string());
    marked((status, Json(body)).into_response(), message)
}

/// Builds a marked Better Auth `APIError` response with an empty JSON body.
pub(crate) fn api_error_empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    marked(response, status.to_string())
}

pub(crate) fn api_redirect(location: HeaderValue) -> Response {
    marked(
        (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        "redirect".into(),
    )
}

fn marked(mut response: Response, message: String) -> Response {
    response
        .extensions_mut()
        .insert(ApiErrorResponse { message });
    response
}

fn auth_error_inner(error: AuthError) -> Response {
    if let Some(response) = custom_error_response(&error) {
        return response;
    }
    let (status, code, message) = match &error {
        error if credential::is_error(error) => credential::details(error),
        AuthError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "TOO_MANY_REQUESTS",
            "Too many sign-in attempts",
        ),
        error if anonymous::is_error(error) => anonymous::details(error),
        AuthError::Forbidden
        | AuthError::SessionNotFresh
        | AuthError::StepUpRequired
        | AuthError::NotFound
        | AuthError::UserAlreadyExists
        | AuthError::UserAlreadyExistsEmail
        | AuthError::LastOwner
        | AuthError::InvalidGuestGrant => access_error_details(&error),
        AuthError::CredentialAccountNotFound
        | AuthError::InvalidPassword
        | AuthError::PasswordTooShort
        | AuthError::PasswordTooLong => password_error_details(&error),
        error if is_passkey_error(error) => passkey_error_details(error),
        AuthError::Username(_) => {
            return crate::username::error::http_error(error, StatusCode::BAD_REQUEST);
        }
        error if is_delete_user_error(error) => delete_user_error_details(error),
        AuthError::InvalidSession => (
            StatusCode::UNAUTHORIZED,
            "INVALID_SESSION",
            "The session is invalid or expired",
        ),
        AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"),
        AuthError::InvalidOrigin
        | AuthError::MissingOrigin
        | AuthError::InvalidCallbackUrl
        | AuthError::InvalidRedirectUrl
        | AuthError::InvalidErrorCallbackUrl
        | AuthError::InvalidNewUserCallbackUrl
        | AuthError::CrossSiteNavigationLogin => request_security_error_details(&error),
        error if oauth::is_error(error) => oauth::details(error),
        AuthError::InvalidConfiguration(_) | AuthError::Storage(_) | AuthError::Worker => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
        ),
    };
    (status, Json(ErrorResponse { code, message })).into_response()
}

fn custom_error_response(error: &AuthError) -> Option<Response> {
    if let Some(response) = plugin::response(error) {
        return Some(response);
    }
    if let Some(response) = oauth::response(error) {
        return Some(response);
    }
    if let Some(response) = have_i_been_pwned::response(error) {
        return Some(response);
    }
    if let AuthError::AccountDisabled(message) = error {
        return Some(
            (
                StatusCode::FORBIDDEN,
                Json(DynamicErrorResponse {
                    code: "BANNED_USER",
                    message,
                }),
            )
                .into_response(),
        );
    }
    if let AuthError::InvalidRequest(message) = error {
        return Some(dynamic_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            message,
        ));
    }
    if let AuthError::PluginApi(error) = error {
        return Some(dynamic_error(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.code,
            &error.message,
        ));
    }
    None
}

pub(super) fn dynamic_error(status: StatusCode, code: &'static str, message: &str) -> Response {
    (status, Json(DynamicErrorResponse { code, message })).into_response()
}

#[derive(Serialize)]
struct DynamicErrorResponse<'a> {
    code: &'static str,
    message: &'a str,
}

#[derive(Serialize)]
struct OwnedErrorResponse {
    code: String,
    message: String,
}
