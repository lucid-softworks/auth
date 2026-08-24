use super::{
    POPUP_MARKER_COOKIE,
    completion::{self, CompletionMessage},
    cookies,
};
use crate::{AuthError, AuthService, PluginRequestContext};
use axum::{http::header, response::Response};
use serde_json::Value;

pub(super) async fn after_response(
    service: &AuthService,
    request: &PluginRequestContext,
    mut response: Response,
) -> Response {
    if !is_callback(&request.path) {
        return response;
    }
    let Some(redirect_to) = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    else {
        return response;
    };
    let marker_cookie = service.plugin_cookie(POPUP_MARKER_COOKIE);
    let Some(marker) = request
        .headers
        .get("cookie")
        .and_then(|header| cookies::request_value(header, &marker_cookie.name))
        .and_then(|value| service.verify_cookie_value(value))
    else {
        return response;
    };
    let Ok(expiry) = cookies::marker(&marker_cookie, "", Some(0.0), true) else {
        return response;
    };
    response = cookies::append(response, expiry);
    let Some((popup_origin, popup_nonce)) = parse_marker(&marker) else {
        return response;
    };
    transform_outcome(service, response, redirect_to, popup_origin, popup_nonce)
}

fn transform_outcome(
    service: &AuthService,
    response: Response,
    redirect_to: String,
    popup_origin: Option<Value>,
    popup_nonce: Value,
) -> Response {
    let token = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| cookies::response_value(value, &service.session_cookie().name));
    if let Some(token) = token.filter(|token| !token.is_empty()) {
        warn_without_bearer(service);
        let completion = completion::render(
            popup_origin,
            CompletionMessage::Success {
                nonce: popup_nonce,
                token,
                redirect_to,
            },
        );
        return replace(response, completion);
    }
    transform_error(service, response, redirect_to, popup_origin, popup_nonce)
}

fn transform_error(
    service: &AuthService,
    response: Response,
    redirect_to: String,
    popup_origin: Option<Value>,
    popup_nonce: Value,
) -> Response {
    let location = match absolute_location(service, &redirect_to) {
        Ok(location) => location,
        Err(error) => return crate::axum::http::auth_error(error),
    };
    let error = location
        .query_pairs()
        .find(|(name, _)| name == "error")
        .map(|(_, value)| value.into_owned());
    let Some(error) = error.filter(|error| !error.is_empty()) else {
        return response;
    };
    let description = location
        .query_pairs()
        .find(|(name, _)| name == "error_description")
        .map(|(_, value)| value.into_owned());
    replace(
        response,
        completion::render(
            popup_origin,
            CompletionMessage::Error {
                nonce: popup_nonce,
                code: error,
                description,
            },
        ),
    )
}

fn parse_marker(marker: &str) -> Option<(Option<Value>, Value)> {
    match serde_json::from_str::<Value>(marker).ok()? {
        Value::Null => None,
        Value::Object(values) => Some((
            values.get("popupOrigin").cloned(),
            values
                .get("popupNonce")
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| Value::String(String::new())),
        )),
        _ => Some((None, Value::String(String::new()))),
    }
}

fn is_callback(path: &str) -> bool {
    path.starts_with("/callback/") || path.starts_with("/oauth2/callback/")
}

fn absolute_location(service: &AuthService, location: &str) -> Result<url::Url, AuthError> {
    if let Ok(location) = url::Url::parse(location) {
        return Ok(location);
    }
    let base =
        url::Url::parse(&service.oauth_base_url()?).map_err(|_| AuthError::InvalidRedirectUrl)?;
    base.join(location)
        .map_err(|_| AuthError::InvalidRedirectUrl)
}

fn replace(original: Response, completion: Response) -> Response {
    let (mut original_parts, _) = original.into_parts();
    let (completion_parts, completion_body) = completion.into_parts();
    original_parts.status = completion_parts.status;
    for (name, value) in &completion_parts.headers {
        original_parts.headers.insert(name, value.clone());
    }
    Response::from_parts(original_parts, completion_body)
}

fn warn_without_bearer(service: &AuthService) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if service
        .plugin_metadata()
        .iter()
        .any(|plugin| plugin.id == "bearer")
        || WARNED.swap(true, Ordering::Relaxed)
    {
        return;
    }
    eprintln!(
        "OAuth popup hands the session token back via postMessage, but the `bearer` plugin is not registered, so an embedded (cross-site iframe) app cannot authenticate with it. Add bearer() to your auth `plugins`."
    );
}
