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
        return next.run(request).await;
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
    let query_callback = request.uri().query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(name, _)| name == "callbackURL")
            .map(|(_, value)| value.into_owned())
    });
    let body_fields = if is_json(request.headers()) {
        let body = std::mem::replace(request.body_mut(), Body::empty());
        let bytes = to_bytes(body, MAX_INSPECTED_BODY_BYTES)
            .await
            .map_err(|_| AuthError::InvalidRequest("request body is too large".into()))?;
        *request.body_mut() = Body::from(bytes.clone());
        json_object(&bytes)
    } else {
        None
    };

    let body_callback = body_fields
        .as_ref()
        .and_then(|fields| fields.get("callbackURL"));
    let callback = truthy_string(body_callback, "callbackURL")?
        .map(str::to_owned)
        .or(query_callback);
    if let Some(callback) = callback {
        validate_callback_url(
            service,
            request.headers(),
            &callback,
            AuthError::InvalidCallbackUrl,
        )?;
    }
    let Some(fields) = body_fields else {
        return Ok(request);
    };
    validate_body_redirect(
        service,
        request.headers(),
        &fields,
        "redirectTo",
        "redirectURL",
        AuthError::InvalidRedirectUrl,
    )?;
    validate_body_redirect(
        service,
        request.headers(),
        &fields,
        "errorCallbackURL",
        "errorCallbackURL",
        AuthError::InvalidErrorCallbackUrl,
    )?;
    validate_body_redirect(
        service,
        request.headers(),
        &fields,
        "newUserCallbackURL",
        "newUserCallbackURL",
        AuthError::InvalidNewUserCallbackUrl,
    )?;
    Ok(request)
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
