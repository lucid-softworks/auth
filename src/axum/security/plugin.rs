use super::{origin_is_trusted, request_origin, validate_callback_url_field};
use crate::{AuthError, AuthService, PluginHttpMethod, PluginRequestSecurity};
use axum::{
    Json,
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub(super) async fn validate_cookie_origin_request(
    service: &AuthService,
    request: Request,
    next: Next,
) -> Response {
    if request.headers().contains_key(header::COOKIE) {
        let Some(origin) = request_origin(request.headers()).filter(|origin| *origin != "null")
        else {
            return crate::axum::error::dynamic_error(
                StatusCode::FORBIDDEN,
                "MISSING_OR_NULL_ORIGIN",
                "Missing or null Origin",
            );
        };
        if !origin_is_trusted(service, request.headers(), origin) {
            return crate::axum::error::dynamic_error(
                StatusCode::FORBIDDEN,
                "INVALID_ORIGIN",
                "Invalid origin",
            );
        }
    }
    match validate_callback_url_field(service, request).await {
        Ok(request) => next.run(request).await,
        Err(AuthError::InvalidCallbackUrl) => crate::axum::error::dynamic_error(
            StatusCode::FORBIDDEN,
            "INVALID_CALLBACK_URL",
            "Invalid callbackURL",
        ),
        Err(AuthError::InvalidRequest(message)) => {
            (StatusCode::BAD_REQUEST, Json(MessageOnlyError { message })).into_response()
        }
        Err(error) => crate::axum::http::auth_error(error),
    }
}

#[derive(serde::Serialize)]
struct MessageOnlyError {
    message: String,
}

pub(super) fn request_security(
    service: &AuthService,
    path: &str,
    method: &Method,
) -> PluginRequestSecurity {
    let relative = if service.base_path() == "/" {
        path
    } else {
        path.strip_prefix(service.base_path()).unwrap_or(path)
    };
    let method = match *method {
        Method::GET => PluginHttpMethod::Get,
        Method::POST => PluginHttpMethod::Post,
        Method::PUT => PluginHttpMethod::Put,
        Method::PATCH => PluginHttpMethod::Patch,
        Method::DELETE => PluginHttpMethod::Delete,
        _ => return PluginRequestSecurity::Browser,
    };
    let mut selected = PluginRequestSecurity::Browser;
    for plugin in service.plugins().plugins() {
        match plugin.request_security(method, relative) {
            PluginRequestSecurity::RawPublic => return PluginRequestSecurity::RawPublic,
            PluginRequestSecurity::CookieOrigin => selected = PluginRequestSecurity::CookieOrigin,
            PluginRequestSecurity::Browser => {}
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, AuthPlugin, MemoryStore, PluginDescriptor};
    use async_trait::async_trait;
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, header},
        routing::post,
    };
    use serde_json::{Value, json};
    use std::{borrow::Cow, sync::Arc};
    use tower::ServiceExt;

    struct CookieOriginPlugin;

    #[async_trait]
    impl AuthPlugin for CookieOriginPlugin {
        fn descriptor(&self) -> PluginDescriptor {
            PluginDescriptor {
                id: "cookie-origin-test",
                display_name: "Cookie origin test",
                version: "1.0.0",
                provenance: crate::PluginProvenance::lucid_extension(),
                dependencies: &[],
                conflicts: &[],
                endpoints: Cow::Borrowed(&[]),
                cookies: &[],
                rate_limits: &[],
                middleware: &[],
                client: None,
            }
        }

        fn request_security(&self, method: PluginHttpMethod, path: &str) -> PluginRequestSecurity {
            if method == PluginHttpMethod::Post && path == "/cookie-origin" {
                PluginRequestSecurity::CookieOrigin
            } else {
                PluginRequestSecurity::Browser
            }
        }

        fn routes(&self, _service: Arc<AuthService>) -> Vec<crate::AxumPluginRoute> {
            vec![crate::AxumPluginRoute::new(
                "/cookie-origin",
                post(|| async { Json(json!({ "success": true })) }),
            )]
        }
    }

    fn application() -> Router {
        let mut config = AuthConfig::new([92_u8; 32]).unwrap();
        config.trust_origin("https://app.example.com").unwrap();
        config.add_plugin(CookieOriginPlugin).unwrap();
        crate::axum::router(Arc::new(AuthService::new(
            Arc::new(MemoryStore::default()),
            config,
        )))
    }

    async fn send(request: Request<Body>) -> (StatusCode, Value) {
        let response = application().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn request() -> axum::http::request::Builder {
        Request::post("/api/auth/cookie-origin")
            .header(header::CONTENT_TYPE, "application/json")
            .header("sec-fetch-site", "cross-site")
    }

    #[tokio::test]
    async fn cookie_origin_mode_ignores_browser_metadata_without_cookies() {
        let (status, body) = send(
            request()
                .header(header::ORIGIN, "https://evil.example")
                .body(Body::from(r#"{"callbackURL":"/dashboard"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({ "success": true }));
    }

    #[tokio::test]
    async fn cookie_origin_mode_enforces_exact_origin_errors_with_cookies() {
        let (status, body) = send(
            request()
                .header(header::COOKIE, "dub_id=lead")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            json!({ "code": "MISSING_OR_NULL_ORIGIN", "message": "Missing or null Origin" })
        );

        let (status, body) = send(
            request()
                .header(header::COOKIE, "dub_id=lead")
                .header(header::ORIGIN, "https://evil.example")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            json!({ "code": "INVALID_ORIGIN", "message": "Invalid origin" })
        );
    }

    #[tokio::test]
    async fn cookie_origin_mode_preserves_callback_validation_order_and_shapes() {
        let (status, body) =
            send(request().body(Body::from(r#"{"callbackURL":[]}"#)).unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            json!({ "message": "Invalid callbackURL: expected a string" })
        );

        let (status, body) = send(
            request()
                .body(Body::from(
                    r#"{"callbackURL":"https://evil.example/after"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            json!({ "code": "INVALID_CALLBACK_URL", "message": "Invalid callbackURL" })
        );
    }
}
