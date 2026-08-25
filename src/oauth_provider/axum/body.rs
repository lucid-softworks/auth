use axum::{
    Form, Json,
    extract::{FromRequest, Request},
    http::header,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;

use super::response::oauth_error;
use crate::OAuthProviderError;

pub(super) struct FormOnly<T>(pub(super) T);

pub(super) struct JsonOnly<T>(pub(super) T);

impl<S, T> FromRequest<S> for FormOnly<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(rejection) = media_type_rejection(&request, "application/x-www-form-urlencoded")
        {
            return Err(rejection);
        }
        Form::<T>::from_request(request, state)
            .await
            .map(|Form(input)| Self(input))
            .map_err(IntoResponse::into_response)
    }
}

impl<S, T> FromRequest<S> for JsonOnly<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(rejection) = media_type_rejection(&request, "application/json") {
            return Err(rejection);
        }
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(input)| Self(input))
            .map_err(IntoResponse::into_response)
    }
}

fn media_type_rejection(request: &Request, allowed: &str) -> Option<Response> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    if media_type.eq_ignore_ascii_case(allowed) {
        return None;
    }
    let presented = if content_type.is_empty() {
        "unknown"
    } else {
        content_type
    };
    Some(oauth_error(&OAuthProviderError::UnsupportedMediaType(
        format!("Content-Type \"{presented}\" is not allowed. Allowed types: {allowed}"),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn media_type_validation_accepts_parameters_and_rejects_other_types() {
        let form = Request::builder()
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .body(Body::empty())
            .unwrap();
        assert!(media_type_rejection(&form, "application/x-www-form-urlencoded").is_none());

        let json = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::empty())
            .unwrap();
        let rejection = media_type_rejection(&json, "application/x-www-form-urlencoded")
            .expect("JSON must be rejected");
        assert_eq!(
            rejection.status(),
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert!(!rejection.headers().contains_key(header::CACHE_CONTROL));
    }
}
