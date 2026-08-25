use axum::{
    body::to_bytes,
    extract::{FromRequest, Request},
    http::header,
    response::Response,
};
use serde_json::{Map, Value};

/// Better Call's optional schema receives `undefined` when the request body is
/// absent. The Autumn handler subsequently spreads it into an object. Keep an
/// explicit JSON `null` distinct so Zod can still reject it.
pub(super) struct OptionalAutumnBody(pub Value);

impl<S> FromRequest<S> for OptionalAutumnBody
where
    S: Send + Sync,
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
            .map_err(|_| invalid("request body is too large"))?;
        if bytes.is_empty() {
            return Ok(Self(Value::Object(Map::new())));
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
        parsed
            .map(Self)
            .map_err(|()| invalid("body must be valid JSON or URL-encoded form data"))
    }
}

fn invalid(message: &str) -> Response {
    crate::axum::api_error(axum::http::StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
}
