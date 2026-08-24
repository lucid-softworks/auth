use super::error::auth_error;
use crate::AuthError;
use axum::{
    body::to_bytes,
    extract::{FromRequest, Request},
    http::header,
    response::Response,
};
use serde::de::DeserializeOwned;

/// Better Auth's credential routes accept JSON and URL-encoded form bodies.
pub(crate) struct BetterAuthBody<T>(pub T);

/// Better Auth endpoints with optional request schemas accept an empty body.
pub(crate) struct OptionalBetterAuthBody<T>(pub T);

impl<S, T> FromRequest<S> for BetterAuthBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::to_owned);
        let bytes = to_bytes(request.into_body(), 1024 * 1024)
            .await
            .map_err(|_| {
                auth_error(AuthError::InvalidRequest(
                    "request body is too large".into(),
                ))
            })?;
        let parsed = match content_type.as_deref() {
            Some(value) if value.eq_ignore_ascii_case("application/json") => {
                serde_json::from_slice(&bytes).map_err(|_| ())
            }
            Some(value) if value.eq_ignore_ascii_case("application/x-www-form-urlencoded") => {
                serde_urlencoded::from_bytes(&bytes).map_err(|_| ())
            }
            _ => Err(()),
        };
        parsed.map(Self).map_err(|()| {
            auth_error(AuthError::InvalidRequest(
                "body must be valid JSON or URL-encoded form data".into(),
            ))
        })
    }
}

impl<S, T> FromRequest<S> for OptionalBetterAuthBody<T>
where
    S: Send + Sync,
    T: Default + DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::to_owned);
        let bytes = to_bytes(request.into_body(), 1024 * 1024)
            .await
            .map_err(|_| {
                auth_error(AuthError::InvalidRequest(
                    "request body is too large".into(),
                ))
            })?;
        if bytes.is_empty() {
            return Ok(Self(T::default()));
        }
        let parsed = match content_type.as_deref() {
            Some(value) if value.eq_ignore_ascii_case("application/json") => {
                serde_json::from_slice(&bytes).map_err(|_| ())
            }
            Some(value) if value.eq_ignore_ascii_case("application/x-www-form-urlencoded") => {
                serde_urlencoded::from_bytes(&bytes).map_err(|_| ())
            }
            _ => Err(()),
        };
        parsed.map(Self).map_err(|()| {
            auth_error(AuthError::InvalidRequest(
                "body must be valid JSON or URL-encoded form data".into(),
            ))
        })
    }
}
