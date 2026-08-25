use super::http::auth_error;
use crate::{AuthService, RateLimitRequest};
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};

const RETRY_AFTER: HeaderName = HeaderName::from_static("x-retry-after");

pub(super) async fn enforce(
    State(service): State<Arc<AuthService>>,
    request: Request,
    next: Next,
) -> Response {
    let path = auth_relative_path(request.uri().path(), service.base_path());
    if service
        .disabled_paths()
        .iter()
        .any(|disabled| disabled == &path)
    {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    let rate_limit_request = RateLimitRequest {
        method: request.method().to_string(),
        path,
        query: request.uri().query().map(str::to_owned),
        headers: request
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>(),
    };
    let client_ip = service.resolve_client_ip(|name| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    });
    let outcome = match service
        .consume_rate_limit_request(&rate_limit_request, client_ip.as_deref())
        .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return next.run(request).await,
        Err(error) => return auth_error(error),
    };
    if outcome.allowed {
        return next.run(request).await;
    }
    let retry_after = outcome.retry_after.unwrap_or_default().to_string();
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({ "message": "Too many requests. Please try again later." })),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after) {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

fn auth_relative_path(path: &str, base_path: &str) -> String {
    let path = path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    let base = base_path.trim_end_matches('/');
    if path == base {
        return "/".into();
    }
    path.strip_prefix(base)
        .filter(|relative| relative.starts_with('/'))
        .unwrap_or(path)
        .trim_end_matches('/')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_paths_like_better_auth() {
        assert_eq!(auth_relative_path("/api/auth", "/api/auth"), "/");
        assert_eq!(
            auth_relative_path("/api/auth/sign-in/email/", "/api/auth"),
            "/sign-in/email"
        );
        assert_eq!(auth_relative_path("/outside", "/api/auth"), "/outside");
    }
}
