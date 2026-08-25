use super::state::{ConfirmationState, set_confirmation};
use crate::{AuthService, OAuthProviderError};
use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::validation::LogoutRedirect;

pub(super) fn is_browser_navigation(headers: &HeaderMap) -> bool {
    if headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        == Some("cors")
    {
        return false;
    }
    headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        == Some("navigate")
        || headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|accept| {
                accept.contains("text/html") || accept.contains("application/xhtml+xml")
            })
}

pub(super) fn confirmation_required(
    service: &AuthService,
    headers: &HeaderMap,
    current: Option<&crate::AuthSession>,
    mut state: ConfirmationState,
) -> Response {
    if !is_browser_navigation(headers) {
        let message = if current.is_some() {
            "User confirmation is required to complete logout"
        } else {
            "No active session is available for logout"
        };
        return protocol_error(headers, &OAuthProviderError::InvalidRequest(message.into()));
    }
    state.session_id = current.map(|session| session.id);
    set_confirmation(service, state, confirmation_page(service))
}

pub(super) fn complete_response(headers: &HeaderMap, redirect: &LogoutRedirect) -> Response {
    if let Some(location) = &redirect.uri {
        let mut response = StatusCode::FOUND.into_response();
        if let Ok(value) = HeaderValue::from_str(location) {
            response.headers_mut().insert(header::LOCATION, value);
        }
        return super::super::response::no_store(response);
    }
    if is_browser_navigation(headers) {
        let note = redirect
            .invalid
            .then_some("The requested post-logout redirect was not registered.");
        return success_page(note);
    }
    super::super::response::no_store(Json(json!(null)).into_response())
}

pub(super) fn protocol_error(headers: &HeaderMap, error: &OAuthProviderError) -> Response {
    if !is_browser_navigation(headers) {
        return super::super::response::oauth_error(error);
    }
    let status = StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::BAD_REQUEST);
    logout_page(
        "Logout error",
        &format!(
            "<main><h1>Logout error</h1><p data-oidc-logout-state=\"error\">{}</p></main>",
            escape_html(super::super::response::description(error))
        ),
        status,
    )
}

fn confirmation_page(service: &AuthService) -> Response {
    let base = service
        .configured_base_url()
        .map(|url| url.as_str().trim_end_matches('/').to_owned())
        .unwrap_or_else(|| service.base_path().trim_end_matches('/').to_owned());
    logout_page(
        "Confirm logout",
        &format!(
            "<main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p><form method=\"post\" data-oidc-logout-confirmation action=\"{}/oauth2/end-session/confirm\"><button type=\"submit\" name=\"action\" value=\"confirm\">Confirm logout</button></form></main>",
            escape_html(&base)
        ),
        StatusCode::OK,
    )
}

fn success_page(note: Option<&str>) -> Response {
    let text = note.map_or_else(
        || "Logged out.".to_owned(),
        |note| format!("Logged out. {note}"),
    );
    logout_page(
        "Logged out",
        &format!(
            "<main><p data-oidc-logout-state=\"logged-out\">{}</p></main>",
            escape_html(&text)
        ),
        StatusCode::OK,
    )
}

fn logout_page(title: &str, body: &str, status: StatusCode) -> Response {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title></head><body>{body}</body></html>",
        escape_html(title)
    );
    let mut response = (status, html).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
