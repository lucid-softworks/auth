use super::super::DashPlugin;
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::json;

pub(super) fn authorization(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
}

pub(super) async fn regular<T: DeserializeOwned>(
    plugin: &DashPlugin,
    headers: &HeaderMap,
) -> Result<T, Response> {
    let claims = plugin
        .verifier()
        .verify_authorization(authorization(headers))
        .await
        .map_err(|_| unauthorized())?;
    serde_json::from_value(claims.0).map_err(|_| unauthorized())
}

pub(super) async fn token<T: DeserializeOwned>(
    plugin: &DashPlugin,
    token: &str,
) -> Result<T, Response> {
    let claims = plugin
        .verifier()
        .verify_token_with(token, true, |claims| {
            Some(serde_json::Value::Object(claims.clone()))
        })
        .await
        .map_err(|_| unauthorized())?;
    serde_json::from_value(claims.0).map_err(|_| unauthorized())
}

pub(super) fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"code": "UNAUTHORIZED", "message": "Invalid API key"})),
    )
        .into_response()
}
