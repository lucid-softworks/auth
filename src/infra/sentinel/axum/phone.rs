use super::http;
use crate::infra::sentinel::{SentinelPlugin, is_valid_phone};
use axum::{extract::Request, http::StatusCode, response::Response};
use serde_json::Value;

const PHONE_PATHS: &[&str] = &[
    "/phone-number/send-otp",
    "/phone-number/verify",
    "/sign-in/phone-number",
    "/phone-number/request-password-reset",
    "/phone-number/reset-password",
];

pub(super) fn process(
    _plugin: &SentinelPlugin,
    request: &Request,
    path: &str,
) -> Result<(), Response> {
    if !PHONE_PATHS.contains(&path) {
        return Ok(());
    }
    let body_phone = request
        .extensions()
        .get::<crate::plugin::CapturedPluginRequestBody>()
        .and_then(|body| body.0.get("phoneNumber"))
        .and_then(Value::as_str);
    let query_phone = request.uri().query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find_map(|(name, value)| (name == "phoneNumber").then(|| value.into_owned()))
    });
    let Some(phone) = body_phone.map(str::to_owned).or(query_phone) else {
        return Ok(());
    };
    if is_valid_phone(&phone) {
        Ok(())
    } else {
        Err(http::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid phone number",
        ))
    }
}
