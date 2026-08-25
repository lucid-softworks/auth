use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

pub(super) const API_KEY_ERROR: &str = "Creem API key is not configured. Please set the apiKey option when initializing the Creem plugin.";

pub(super) fn success(value: Value) -> Response {
    Json(value).into_response()
}

pub(super) fn error(message: &str) -> Response {
    success(json!({"error": message}))
}

pub(super) fn message(message: &str) -> Response {
    success(json!({"message": message}))
}

pub(super) fn validation_error(message: &str) -> Response {
    crate::axum::api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", message)
}

pub(super) fn parse<T: DeserializeOwned>(value: Value) -> Result<T, Box<Response>> {
    serde_json::from_value(value).map_err(|_| Box::new(validation_error("Invalid input")))
}

pub(super) async fn session(
    service: &crate::AuthService,
    headers: &HeaderMap,
) -> Option<crate::SessionWithUser> {
    crate::axum::http::current_session(service, headers).await
}

pub(super) fn truthy(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

pub(super) fn user_string<'a>(session: &'a crate::SessionWithUser, field: &str) -> Option<&'a str> {
    session
        .user
        .additional_fields
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}
