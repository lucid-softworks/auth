use super::http::auth_error;
use crate::{AuthError, AuthService, TrustedOrigin, origin::safe_relative_callback};
use axum::{
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, Method, header},
    middleware::Next,
    response::Response,
};
use serde_json::{Map, Value};
use std::sync::Arc;

const MAX_INSPECTED_BODY_BYTES: usize = 1024 * 1024;

pub(super) async fn validate_browser_request(
    State(service): State<Arc<AuthService>>,
    request: Request,
    next: Next,
) -> Response {
    if is_safe_method(request.method()) {
        return match validate_redirect_fields(&service, request).await {
            Ok(request) => next.run(request).await,
            Err(error) => auth_error(error),
        };
    }
    let headers = request.headers();
    let fetch_site = header_text(headers, "sec-fetch-site");
    let fetch_mode = header_text(headers, "sec-fetch-mode");
    let fetch_dest = header_text(headers, "sec-fetch-dest");
    if fetch_site == Some("cross-site") && fetch_mode == Some("navigate") {
        return auth_error(AuthError::CrossSiteNavigationLogin);
    }

    let supplied_origin = request_origin(headers);
    let browser_metadata_present = fetch_site.is_some()
        || fetch_mode.is_some()
        || fetch_dest.is_some()
        || supplied_origin.is_some();
    let uses_cookies = headers.contains_key(header::COOKIE);
    if browser_metadata_present || uses_cookies {
        let Some(origin) = supplied_origin.filter(|origin| *origin != "null") else {
            return auth_error(AuthError::MissingOrigin);
        };
        if !origin_is_trusted(&service, headers, origin) {
            return auth_error(AuthError::InvalidOrigin);
        }
    }
    match validate_redirect_fields(&service, request).await {
        Ok(request) => next.run(request).await,
        Err(error) => auth_error(error),
    }
}

fn validate_callback_url(
    service: &AuthService,
    headers: &HeaderMap,
    callback_url: &str,
    error: AuthError,
) -> Result<(), AuthError> {
    if safe_relative_callback(callback_url) || origin_is_trusted(service, headers, callback_url) {
        Ok(())
    } else {
        Err(error)
    }
}

async fn validate_redirect_fields(
    service: &AuthService,
    mut request: Request,
) -> Result<Request, AuthError> {
    let query_fields = request.uri().query().map(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .map(|(name, value)| (name.into_owned(), Value::String(value.into_owned())))
            .collect::<Map<_, _>>()
    });
    let body_fields = if is_inspected_body(request.headers()) {
        let body = std::mem::replace(request.body_mut(), Body::empty());
        let bytes = to_bytes(body, MAX_INSPECTED_BODY_BYTES)
            .await
            .map_err(|_| AuthError::InvalidRequest("request body is too large".into()))?;
        *request.body_mut() = Body::from(bytes.clone());
        if is_json(request.headers()) {
            json_object(&bytes)
        } else {
            form_object(&bytes)
        }
    } else {
        None
    };

    if let Some(fields) = query_fields {
        validate_redirect_map(service, request.headers(), &fields)?;
    }
    if let Some(fields) = body_fields {
        validate_redirect_map(service, request.headers(), &fields)?;
    }
    Ok(request)
}

fn validate_redirect_map(
    service: &AuthService,
    headers: &HeaderMap,
    fields: &Map<String, Value>,
) -> Result<(), AuthError> {
    validate_body_redirect(
        service,
        headers,
        fields,
        "callbackURL",
        "callbackURL",
        AuthError::InvalidCallbackUrl,
    )?;
    validate_body_redirect(
        service,
        headers,
        fields,
        "redirectTo",
        "redirectTo",
        AuthError::InvalidRedirectUrl,
    )?;
    validate_body_redirect(
        service,
        headers,
        fields,
        "errorCallbackURL",
        "errorCallbackURL",
        AuthError::InvalidErrorCallbackUrl,
    )?;
    validate_body_redirect(
        service,
        headers,
        fields,
        "newUserCallbackURL",
        "newUserCallbackURL",
        AuthError::InvalidNewUserCallbackUrl,
    )?;
    Ok(())
}

fn validate_body_redirect(
    service: &AuthService,
    headers: &HeaderMap,
    fields: &Map<String, Value>,
    field: &str,
    label: &str,
    error: AuthError,
) -> Result<(), AuthError> {
    if let Some(value) = truthy_string(fields.get(field), label)? {
        validate_callback_url(service, headers, value, error)?;
    }
    Ok(())
}

fn truthy_string<'a>(value: Option<&'a Value>, label: &str) -> Result<Option<&'a str>, AuthError> {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(None),
        Some(Value::Number(number)) if number.as_f64() == Some(0.0) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(AuthError::InvalidRequest(format!(
            "Invalid {label}: expected a string"
        ))),
    }
}

fn json_object(bytes: &Bytes) -> Option<Map<String, Value>> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.as_object().cloned())
}

fn form_object(bytes: &Bytes) -> Option<Map<String, Value>> {
    let mut fields = Map::new();
    for (name, value) in url::form_urlencoded::parse(bytes) {
        fields.insert(name.into_owned(), Value::String(value.into_owned()));
    }
    Some(fields)
}

fn is_inspected_body(headers: &HeaderMap) -> bool {
    is_json(headers)
        || header_text(headers, header::CONTENT_TYPE.as_str())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
}

fn is_json(headers: &HeaderMap) -> bool {
    header_text(headers, header::CONTENT_TYPE.as_str())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}

fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn request_origin(headers: &HeaderMap) -> Option<&str> {
    header_text(headers, header::ORIGIN.as_str()).or_else(|| header_text(headers, "referer"))
}

fn origin_is_trusted(service: &AuthService, headers: &HeaderMap, candidate: &str) -> bool {
    service.trusts_origin(candidate)
        || request_host_origin(service, headers).is_some_and(|origin| {
            TrustedOrigin::parse(&origin).is_ok_and(|trusted| trusted.matches(candidate))
        })
}

fn request_host_origin(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    let host = header_text(headers, header::HOST.as_str())?;
    if host.contains(['/', '\\', '@']) {
        return None;
    }
    let scheme = if service.cookie_secure() {
        "https"
    } else {
        "http"
    };
    Some(format!("{scheme}://{host}"))
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
