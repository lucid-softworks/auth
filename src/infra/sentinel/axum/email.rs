use super::http;
use crate::infra::sentinel::{
    SentinelPlugin, email_normalization_enabled, email_validation_enabled,
    is_valid_email_format_local, normalize_email,
};
use axum::{extract::Request, http::StatusCode, response::Response};
use serde_json::Value;

const REGISTRATION_PATHS: &[&str] = &[
    "/sign-up/email",
    "/change-email",
    "/organization/invite-member",
    "/dash/organization/invite-member",
    "/dash/create-user",
    "/dash/update-user",
];
const AUTH_PATHS: &[&str] = &[
    "/sign-in/email",
    "/sign-in/email-otp",
    "/sign-in/magic-link",
    "/forget-password",
    "/forget-password/email-otp",
    "/request-password-reset",
    "/send-verification-email",
    "/email-otp/verify-email",
    "/email-otp/reset-password",
    "/email-otp/create-verification-otp",
    "/email-otp/get-verification-otp",
    "/email-otp/send-verification-otp",
];

pub(super) fn is_email_path(path: &str) -> bool {
    REGISTRATION_PATHS.contains(&path) || AUTH_PATHS.contains(&path)
}

pub(super) async fn process(
    plugin: &SentinelPlugin,
    request: &mut Request,
    path: &str,
) -> Result<(), Response> {
    if !is_email_path(path) {
        return Ok(());
    }
    let mut body = request
        .extensions()
        .get::<crate::plugin::CapturedPluginRequestBody>()
        .map(|body| body.0.clone());
    let field = if path == "/change-email" {
        "newEmail"
    } else {
        "email"
    };
    let query_email = request.uri().query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find_map(|(name, value)| (name == "email").then(|| value.into_owned()))
    });
    let Some(email) = body
        .as_ref()
        .and_then(|body| body.get(field))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or(query_email)
    else {
        return Ok(());
    };
    let normalized = if email_normalization_enabled(&plugin.options().security) {
        normalize_email(&email, &plugin.options().security)
    } else {
        email
    };
    if let Some(body) = body.as_mut() {
        if let Some(object) = body.as_object_mut() {
            object.insert(field.into(), Value::String(normalized.clone()));
        }
        http::replace_json_body(request, body.clone());
    } else {
        http::replace_query_value(request, "email", &normalized);
    }
    if !email_validation_enabled(&plugin.options().security) {
        return Ok(());
    }
    let trimmed = normalized.trim();
    if !is_valid_email_format_local(trimmed) {
        return Err(http::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid email",
        ));
    }
    if REGISTRATION_PATHS.contains(&path) {
        let result = plugin.security_client().validate_email(trimmed).await;
        if !result.valid {
            return Err(http::error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                result
                    .message
                    .unwrap_or("This email address appears to be invalid"),
            ));
        }
    }
    Ok(())
}
