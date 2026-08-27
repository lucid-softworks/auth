use super::input::{OAuthProxyQuery, query, required_query_error};
use crate::AuthService;
use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    extract::RawQuery,
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tower::ServiceExt as _;

pub(super) async fn initialize(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(options): Extension<Arc<super::ElectronOptions>>,
    RawQuery(raw_query): RawQuery,
    mut headers: HeaderMap,
) -> Response {
    let query = match query::<OAuthProxyQuery>(raw_query.as_deref()) {
        Ok(query) => query,
        Err(()) => return required_query_error("provider"),
    };
    if query.provider.is_empty() {
        return super::input::validation_error(
            "[query.provider] Too small: expected string to have >=1 characters",
        );
    }
    let Some(origin) = service
        .configured_base_url()
        .map(|url| url.origin().ascii_serialization())
        .and_then(|origin| HeaderValue::from_str(&origin).ok())
    else {
        return crate::axum::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "An unknown error occurred.",
        );
    };
    headers.insert(header::ORIGIN, origin);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let inner_query = {
        let mut query_string = url::form_urlencoded::Serializer::new(String::new());
        query_string.append_pair("client_id", &options.client_id);
        query_string.append_pair("code_challenge", &query.code_challenge);
        query_string.append_pair("state", &query.state);
        query_string.finish()
    };
    let uri = format!(
        "{}/sign-in/social?{}",
        service.base_path().trim_end_matches('/'),
        inner_query
    );
    let request = Request::builder().method("POST").uri(uri).body(Body::from(
        serde_json::to_vec(&serde_json::json!({ "provider": query.provider })).unwrap_or_default(),
    ));
    let mut request = match request {
        Ok(request) => request,
        Err(_) => return internal_error("An unknown error occurred."),
    };
    *request.headers_mut() = headers;
    let inner = match crate::axum::router::<()>(service).oneshot(request).await {
        Ok(response) => response,
        Err(error) => match error {},
    };
    project_inner(inner).await
}

async fn project_inner(inner: Response) -> Response {
    let status = inner.status();
    let cookies = inner
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let bytes = match to_bytes(inner.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => return internal_error("An unknown error occurred."),
    };
    let data =
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        let message = data
            .get("message")
            .and_then(serde_json::Value::as_str)
            .filter(|message| !message.is_empty())
            .unwrap_or("An unknown error occurred.");
        return internal_error(message);
    }

    let mut response = if data.get("url").is_some_and(javascript_truthy)
        && data.get("redirect").is_some_and(javascript_truthy)
    {
        let Some(location) = data
            .get("url")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| HeaderValue::from_str(value).ok())
        else {
            return internal_error("An unknown error occurred.");
        };
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::FOUND;
        response.headers_mut().insert(header::LOCATION, location);
        response
    } else {
        Json(data).into_response()
    };
    for cookie in cookies {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

fn javascript_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(value) => value.as_f64() != Some(0.0),
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => true,
    }
}

fn internal_error(message: &str) -> Response {
    crate::axum::api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        message,
    )
}
