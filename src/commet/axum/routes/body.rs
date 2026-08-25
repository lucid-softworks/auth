use axum::{
    body::to_bytes,
    extract::{FromRequest, Request},
    http::header,
    response::Response,
};
use serde_json::Value;

pub(super) struct CommetBody(pub Option<Value>);

impl<S> FromRequest<S> for CommetBody
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .map(str::to_owned);
        let is_json = content_type
            .as_deref()
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .is_some_and(|value| value.eq_ignore_ascii_case("application/json"));
        let bytes = to_bytes(request.into_body(), 1024 * 1024)
            .await
            .map_err(|_| {
                super::super::support::coded(
                    axum::http::StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid JSON in request body",
                )
            })?;
        if bytes.is_empty() {
            if content_type.is_some() && !is_json {
                return Err(unsupported_content_type(content_type.as_deref()));
            }
            return Ok(Self(None));
        }
        if !is_json {
            return Err(unsupported_content_type(content_type.as_deref()));
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map(Self)
            .map_err(|_| {
                super::super::support::coded(
                    axum::http::StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid JSON in request body",
                )
            })
    }
}

fn unsupported_content_type(content_type: Option<&str>) -> Response {
    let message = match content_type {
        Some(content_type) => format!(
            "Content-Type \"{content_type}\" is not allowed. Allowed types: application/json"
        ),
        None => "Content-Type is required. Allowed types: application/json".into(),
    };
    super::super::support::coded(
        axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "UNSUPPORTED_MEDIA_TYPE",
        message,
    )
}
