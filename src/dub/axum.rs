use super::DubPlugin;
use axum::{
    Extension, Json,
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::Value;
use std::sync::Arc;

pub(crate) fn routes(
    _service: Arc<crate::AuthService>,
    plugin: DubPlugin,
) -> Vec<crate::AxumPluginRoute> {
    vec![crate::AxumPluginRoute::new(
        "/dub/link",
        post(link).layer::<_, std::convert::Infallible>(Extension(plugin)),
    )]
}

async fn link(
    Extension(plugin): Extension<DubPlugin>,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    if let Err(message) = validate_callback_url(&body) {
        return crate::axum::api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", message);
    }
    if plugin.options.oauth.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message": "Dub OAuth is not configured"})),
        )
            .into_response();
    }
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::empty())
        .expect("static Dub compatibility response is valid")
}

fn validate_callback_url(body: &Value) -> Result<&str, &'static str> {
    let Some(object) = body.as_object() else {
        return Err(match body {
            Value::Null => "[body] Expected object, received null",
            Value::Bool(_) => "[body] Expected object, received boolean",
            Value::Number(_) => "[body] Expected object, received number",
            Value::String(_) => "[body] Expected object, received string",
            Value::Array(_) => "[body] Expected object, received array",
            Value::Object(_) => unreachable!(),
        });
    };
    let value = object
        .get("callbackURL")
        .ok_or("[body.callbackURL] Required")?;
    let value = match value {
        Value::String(value) => value,
        Value::Null => return Err("[body.callbackURL] Expected string, received null"),
        Value::Bool(_) => return Err("[body.callbackURL] Expected string, received boolean"),
        Value::Number(_) => return Err("[body.callbackURL] Expected string, received number"),
        Value::Array(_) => return Err("[body.callbackURL] Expected string, received array"),
        Value::Object(_) => return Err("[body.callbackURL] Expected string, received object"),
    };
    url::Url::parse(value)
        .map(|_| value.as_str())
        .map_err(|_| "[body.callbackURL] Invalid url")
}

#[cfg(test)]
mod tests {
    use super::validate_callback_url;
    use serde_json::json;

    #[test]
    fn callback_url_matches_zod_3_required_type_and_url_errors() {
        for (value, expected) in [
            (json!({}), "[body.callbackURL] Required"),
            (
                json!({"callbackURL": null}),
                "[body.callbackURL] Expected string, received null",
            ),
            (
                json!({"callbackURL": false}),
                "[body.callbackURL] Expected string, received boolean",
            ),
            (
                json!({"callbackURL": 0}),
                "[body.callbackURL] Expected string, received number",
            ),
            (json!({"callbackURL": ""}), "[body.callbackURL] Invalid url"),
            (
                json!({"callbackURL": "/dashboard"}),
                "[body.callbackURL] Invalid url",
            ),
            (
                json!({"callbackUrl": "https://app.example/dashboard"}),
                "[body.callbackURL] Required",
            ),
        ] {
            assert_eq!(validate_callback_url(&value), Err(expected));
        }
        assert_eq!(
            validate_callback_url(&json!({
                "callbackURL": "https://app.example/dashboard",
                "unknown": "stripped"
            })),
            Ok("https://app.example/dashboard")
        );
    }
}
