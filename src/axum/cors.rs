use crate::{AuthError, AuthService};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

pub(super) async fn credentialed_trusted_origins(
    State(service): State<Arc<AuthService>>,
    request: Request,
    next: Next,
) -> Response {
    if !service.cors_enabled() {
        return next.run(request).await;
    }
    let origin = request.headers().get(header::ORIGIN).cloned();
    let trusted = origin
        .as_ref()
        .and_then(|origin| origin.to_str().ok())
        .is_some_and(|origin| service.trusts_origin(origin));

    if request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
    {
        if !trusted {
            return super::http::auth_error(AuthError::InvalidOrigin);
        }
        let requested_headers = request
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .cloned();
        let mut response = (StatusCode::NO_CONTENT, Body::empty()).into_response();
        add_cors_headers(response.headers_mut(), origin, requested_headers);
        return response;
    }

    let mut response = next.run(request).await;
    if trusted {
        add_cors_headers(response.headers_mut(), origin, None);
    }
    response
}

fn add_cors_headers(
    headers: &mut HeaderMap,
    origin: Option<HeaderValue>,
    requested_headers: Option<HeaderValue>,
) {
    if let Some(origin) = origin {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    if let Some(requested_headers) = requested_headers {
        headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested_headers);
    }
    headers.insert(
        header::VARY,
        HeaderValue::from_static(
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        ),
    );
}
