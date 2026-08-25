#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

mod customer;
mod reference;

pub(super) use customer::{
    CustomerRequest, customer_id, organization_snapshot, session_customer_id, session_snapshot,
    user_snapshot,
};
pub(super) use reference::{authorize_reference, require_subscription, resolve_reference};

use crate::chargebee::{
    ChargebeeApiError, ChargebeeCallbackContext, ChargebeeErrorCode, ChargebeeProviderError,
};
use crate::{AuthService, SessionWithUser};
use axum::{
    Json,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde_json::Value;
use std::collections::BTreeMap;

const ENCODE_URI_COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub(super) fn success(value: Value) -> Response {
    Json(value).into_response()
}

pub(super) fn validation_error(message: impl Into<String>) -> Response {
    crate::axum::api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", message)
}

pub(super) fn error(code: ChargebeeErrorCode, status: StatusCode) -> Response {
    crate::axum::api_error(status, code.code(), code.message())
}

pub(super) fn literal_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    crate::axum::api_error(status, code, message)
}

pub(super) fn api_error(error: ChargebeeApiError) -> Response {
    crate::axum::api_error(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        error.code,
        error.message,
    )
}

pub(super) fn provider_error(error: ChargebeeProviderError) -> Response {
    let message = provider_message(error.message);
    crate::axum::api_error(
        StatusCode::BAD_REQUEST,
        error
            .api_error_code
            .unwrap_or_else(|| "BAD_REQUEST".to_owned()),
        message,
    )
}

fn provider_message(message: String) -> String {
    if message.is_empty() {
        "An error occurred".to_owned()
    } else {
        message
    }
}

pub(super) fn internal_error(message: impl std::fmt::Display) -> Response {
    tracing::error!(message = %message, "Chargebee route failed");
    crate::axum::api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        "Authentication failed",
    )
}

pub(super) async fn session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Result<SessionWithUser, Response> {
    crate::axum::http::current_session(service, headers)
        .await
        .ok_or_else(|| literal_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"))
}

pub(super) fn callback_context(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
) -> ChargebeeCallbackContext {
    ChargebeeCallbackContext {
        method: Some(method.to_owned()),
        path: Some(path.to_owned()),
        query: query.map(str::to_owned),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>(),
    }
}

pub(super) fn validate_origin(
    service: &AuthService,
    headers: &HeaderMap,
    value: &str,
) -> Result<(), Response> {
    if value.is_empty() {
        return Ok(());
    }
    crate::axum::validate_trusted_origin_value(service, headers, value).map_err(|_| {
        literal_error(
            StatusCode::FORBIDDEN,
            "INVALID_CALLBACK_URL",
            "The callback URL is not trusted",
        )
    })
}

pub(super) fn absolute_url(service: &AuthService, headers: &HeaderMap, value: &str) -> String {
    if value
        .split_once(':')
        .is_some_and(|(scheme, _)| valid_scheme(scheme))
    {
        return value.to_owned();
    }
    let base = request_base_url(service, headers);
    format!(
        "{}{}",
        base.trim_end_matches('/'),
        if value.starts_with('/') {
            value.to_owned()
        } else {
            format!("/{value}")
        }
    )
}

fn request_base_url(service: &AuthService, headers: &HeaderMap) -> String {
    if let Some(configured) = service.configured_base_url() {
        let mut configured = configured.clone();
        if configured.path() == "/" {
            configured.set_path(service.base_path());
        }
        return configured.as_str().trim_end_matches('/').to_owned();
    }
    let scheme = if service.trusted_proxy_headers() {
        first_header(headers, "x-forwarded-proto")
            .filter(|scheme| matches!(*scheme, "http" | "https"))
            .unwrap_or(if service.cookie_secure() {
                "https"
            } else {
                "http"
            })
    } else if service.cookie_secure() {
        "https"
    } else {
        "http"
    };
    let host = if service.trusted_proxy_headers() {
        first_header(headers, "x-forwarded-host")
            .or_else(|| first_header(headers, header::HOST.as_str()))
    } else {
        first_header(headers, header::HOST.as_str())
    }
    .unwrap_or("localhost");
    format!("{scheme}://{host}{}", service.base_path())
}

fn first_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn valid_scheme(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|value| value.is_ascii_alphabetic())
        && chars.all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '-' | '.'))
}

pub(super) fn encode_component(value: &str) -> String {
    utf8_percent_encode(value, ENCODE_URI_COMPONENT).to_string()
}

pub(super) fn redirect(location: String) -> Response {
    match axum::http::HeaderValue::from_str(&location) {
        Ok(value) => {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        Err(error) => internal_error(error),
    }
}

pub(super) fn javascript_quantity(value: Option<f64>) -> f64 {
    value.filter(|value| *value != 0.0).unwrap_or(1.0)
}

pub(super) fn json_number(value: f64) -> Value {
    serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore};
    use std::sync::Arc;

    fn service(base_url: Option<&str>) -> AuthService {
        let mut config = AuthConfig::new([181; 32]).unwrap();
        if let Some(base_url) = base_url {
            config.set_base_url(base_url).unwrap();
        }
        AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap()
    }

    #[test]
    fn javascript_quantity_turns_both_zeroes_into_one() {
        assert_eq!(javascript_quantity(None), 1.0);
        assert_eq!(javascript_quantity(Some(0.0)), 1.0);
        assert_eq!(javascript_quantity(Some(-0.0)), 1.0);
        assert_eq!(javascript_quantity(Some(-2.5)), -2.5);
    }

    #[test]
    fn component_encoding_matches_encode_uri_component_edges() {
        assert_eq!(encode_component("/success?a=b c"), "%2Fsuccess%3Fa%3Db%20c");
        assert_eq!(encode_component("-_.!~*'()"), "-_.!~*'()");
    }

    #[test]
    fn scheme_detection_keeps_the_artifacts_non_http_behavior() {
        assert!(valid_scheme("mailto"));
        assert!(valid_scheme("x+y-z.1"));
        assert!(!valid_scheme("1https"));
    }

    #[test]
    fn empty_origins_are_skipped_and_empty_provider_messages_get_fallback() {
        let service = service(None);
        assert!(validate_origin(&service, &HeaderMap::new(), "").is_ok());
        assert_eq!(provider_message(String::new()), "An error occurred");
        assert_eq!(provider_message("provider".into()), "provider");
    }

    #[test]
    fn request_base_uses_host_when_static_base_is_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "auth.example.test".parse().unwrap());
        assert_eq!(
            absolute_url(&service(None), &headers, "/success"),
            "http://auth.example.test/api/auth/success",
        );
    }

    #[test]
    fn configured_origin_gets_base_path_but_custom_path_is_preserved() {
        let headers = HeaderMap::new();
        assert_eq!(
            absolute_url(
                &service(Some("https://auth.example.test")),
                &headers,
                "/success",
            ),
            "https://auth.example.test/api/auth/success",
        );
        assert_eq!(
            absolute_url(
                &service(Some("https://auth.example.test/custom")),
                &headers,
                "/success",
            ),
            "https://auth.example.test/custom/success",
        );
    }
}
