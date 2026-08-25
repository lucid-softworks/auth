use super::*;

#[derive(Clone)]
struct LifecycleContractPlugin;

#[derive(Clone)]
struct NoopMiddlewarePlugin;

#[async_trait::async_trait]
impl crate::AuthPlugin for NoopMiddlewarePlugin {
    fn descriptor(&self) -> crate::PluginDescriptor {
        crate::PluginDescriptor {
            id: "noop-middleware",
            display_name: "No-op middleware",
            version: INSTRUMENTATION_VERSION,
            provenance: crate::PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Owned(vec![crate::PluginEndpoint {
                method: crate::PluginHttpMethod::Get,
                path: std::borrow::Cow::Borrowed("/noop-middleware"),
                client_method: "noopMiddleware",
            }]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[crate::PluginMiddleware { id: "noop" }],
            client: None,
        }
    }

    fn routes(&self, _service: std::sync::Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        vec![crate::AxumPluginRoute::new(
            "/noop-middleware",
            axum::routing::get(|| async { "ok" }),
        )]
    }
}

#[async_trait::async_trait]
impl crate::AuthPlugin for LifecycleContractPlugin {
    fn descriptor(&self) -> crate::PluginDescriptor {
        crate::PluginDescriptor {
            id: "lifecycle-contract",
            display_name: "Lifecycle contract",
            version: INSTRUMENTATION_VERSION,
            provenance: crate::PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Owned(vec![
                crate::PluginEndpoint {
                    method: crate::PluginHttpMethod::Get,
                    path: std::borrow::Cow::Borrowed("/lifecycle-contract"),
                    client_method: "lifecycleContract",
                },
                crate::PluginEndpoint {
                    method: crate::PluginHttpMethod::Get,
                    path: std::borrow::Cow::Borrowed("/lifecycle-fallback"),
                    client_method: "namespace.fallback",
                },
            ]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[crate::PluginMiddleware { id: "contract" }],
            client: None,
        }
    }

    fn contributes_on_request(&self) -> bool {
        true
    }

    async fn on_request(
        &self,
        _service: &crate::AuthService,
        request: axum::extract::Request,
    ) -> Result<axum::extract::Request, axum::response::Response> {
        Ok(request)
    }

    fn contributes_on_response(&self) -> bool {
        true
    }

    fn contributes_middleware(&self) -> bool {
        true
    }

    fn middleware(
        &self,
        route: axum::routing::MethodRouter,
        _service: std::sync::Arc<crate::AuthService>,
    ) -> axum::routing::MethodRouter {
        route.layer(axum::middleware::from_fn(
            |request: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut response = next.run(request).await;
                response
                    .headers_mut()
                    .insert("x-contract", "present".parse().unwrap());
                response
            },
        ))
    }

    fn open_api_endpoints(&self) -> Vec<crate::OpenApiEndpoint> {
        let mut endpoint =
            crate::OpenApiEndpoint::new("/lifecycle-contract", vec![crate::PluginHttpMethod::Get]);
        endpoint.operation_id = Some("explicitLifecycleContract".into());
        vec![endpoint]
    }

    async fn after_response(
        &self,
        _service: &crate::AuthService,
        _request: &crate::PluginRequestContext,
        response: axum::response::Response,
    ) -> axum::response::Response {
        response
    }

    fn routes(&self, _service: std::sync::Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        vec![
            crate::AxumPluginRoute::new(
                "/lifecycle-contract",
                axum::routing::get(|| async { "ok" }),
            ),
            crate::AxumPluginRoute::new(
                "/lifecycle-fallback",
                axum::routing::get(|| async { "ok" }),
            ),
        ]
    }
}

#[tokio::test]
async fn http_dispatch_uses_route_template_operation_id_and_hierarchy() {
    use axum::{body::Body, http::Request};
    use std::sync::Arc;
    use tower::ServiceExt;
    let _ = exporter();
    let service = Arc::new(crate::AuthService::new(
        Arc::new(crate::MemoryStore::default()),
        crate::AuthConfig::new([66_u8; 32]).unwrap(),
    ));
    let response = crate::axum::router::<()>(service)
        .oneshot(
            Request::builder()
                .uri("/api/auth/get-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let dispatch = find("GET /get-session");
    let handler = find("handler /get-session");
    assert_eq!(handler.parent_span_id, dispatch.span_context.span_id());
    assert!(dispatch.attributes.iter().any(|item| {
        item.key.as_str() == ATTR_OPERATION_ID
            && item.value == Value::String("getSession".to_owned().into())
    }));
}

#[tokio::test]
async fn endpoint_errors_and_api_redirects_keep_exact_hierarchy() {
    use axum::http::{HeaderValue, StatusCode};
    let _ = exporter();
    let error = EndpointSpanMetadata::new("POST", "/contract-error", "contractError");
    let (dispatch_name, dispatch_attributes) = error.dispatch_span();
    let error_response = with_span_async(dispatch_name, dispatch_attributes, async {
        let (handler_name, handler_attributes) = error.handler_span();
        with_http_handler_span(handler_name, handler_attributes, async {
            crate::axum::api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "ordinary endpoint error",
            )
        })
        .await
    })
    .await;
    assert_eq!(error_response.status(), StatusCode::BAD_REQUEST);

    let redirect = EndpointSpanMetadata::new("GET", "/contract-redirect", "contractRedirect");
    let (dispatch_name, dispatch_attributes) = redirect.dispatch_span();
    let redirect_response = with_span_async(dispatch_name, dispatch_attributes, async {
        let (handler_name, handler_attributes) = redirect.handler_span();
        with_http_handler_span(handler_name, handler_attributes, async {
            crate::axum::api_redirect(HeaderValue::from_static("/destination"))
        })
        .await
    })
    .await;
    assert_eq!(redirect_response.status(), StatusCode::FOUND);

    let error_dispatch = find("POST /contract-error");
    let error_handler = find("handler /contract-error");
    assert_eq!(error_dispatch.status, Status::Unset);
    assert_eq!(
        error_handler.status,
        Status::error("ordinary endpoint error")
    );
    assert_eq!(error_handler.events.len(), 1);
    assert_eq!(
        error_handler.parent_span_id,
        error_dispatch.span_context.span_id()
    );
    let redirect_dispatch = find("GET /contract-redirect");
    let redirect_handler = find("handler /contract-redirect");
    assert_eq!(redirect_dispatch.status, Status::Unset);
    assert_eq!(redirect_handler.status, Status::Ok);
    assert!(redirect_handler.events.is_empty());
    assert_eq!(
        redirect_handler.parent_span_id,
        redirect_dispatch.span_context.span_id()
    );
}

#[tokio::test]
async fn only_contributed_plugin_lifecycle_callbacks_emit_spans() {
    use axum::{body::Body, http::Request};
    use std::sync::Arc;
    use tower::ServiceExt;
    let _ = exporter();
    let mut config = crate::AuthConfig::new([67_u8; 32]).unwrap();
    config.add_plugin(LifecycleContractPlugin).unwrap();
    let service = Arc::new(crate::AuthService::new(
        Arc::new(crate::MemoryStore::default()),
        config,
    ));
    assert_eq!(
        service
            .plugins()
            .endpoint_operation_id(crate::PluginHttpMethod::Get, "/lifecycle-contract"),
        "explicitLifecycleContract"
    );
    assert_eq!(
        service
            .plugins()
            .endpoint_operation_id(crate::PluginHttpMethod::Get, "/lifecycle-fallback"),
        "namespace.fallback"
    );
    assert_eq!(
        service
            .plugins()
            .endpoint_operation_id(crate::PluginHttpMethod::Get, "/unknown"),
        "/unknown"
    );
    let response = crate::axum::router::<()>(service)
        .oneshot(
            Request::builder()
                .uri("/api/auth/lifecycle-contract")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let on_request = find("onRequest lifecycle-contract");
    let middleware = find("middleware /lifecycle-contract lifecycle-contract");
    let on_response = find("onResponse lifecycle-contract");
    assert_eq!(on_request.attributes.len(), 2);
    assert_eq!(middleware.attributes.len(), 3);
    assert_eq!(on_response.attributes.len(), 3);
    assert!(on_response.attributes.iter().any(|item| {
        item.key.as_str() == ATTR_HTTP_RESPONSE_STATUS_CODE && item.value == Value::I64(200)
    }));
    let dispatch = find("GET /lifecycle-contract");
    assert!(dispatch.attributes.iter().any(|item| {
        item.key.as_str() == ATTR_OPERATION_ID
            && item.value == Value::String("explicitLifecycleContract".into())
    }));

    let response = crate::axum::router::<()>(Arc::new(crate::AuthService::new(
        Arc::new(crate::MemoryStore::default()),
        {
            let mut config = crate::AuthConfig::new([68_u8; 32]).unwrap();
            config.add_plugin(LifecycleContractPlugin).unwrap();
            config
        },
    )))
    .oneshot(
        Request::builder()
            .uri("/api/auth/lifecycle-fallback")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(response.headers()["x-contract"], "present");
    let dispatch = find("GET /lifecycle-fallback");
    assert!(dispatch.attributes.iter().any(|item| {
        item.key.as_str() == ATTR_OPERATION_ID
            && item.value == Value::String("namespace.fallback".into())
    }));
}

#[tokio::test]
async fn default_plugin_middleware_does_not_emit_a_span() {
    use axum::{body::Body, http::Request};
    use std::sync::Arc;
    use tower::ServiceExt;
    let _ = exporter();
    let mut config = crate::AuthConfig::new([69_u8; 32]).unwrap();
    config.add_plugin(NoopMiddlewarePlugin).unwrap();
    let service = Arc::new(crate::AuthService::new(
        Arc::new(crate::MemoryStore::default()),
        config,
    ));
    let response = crate::axum::router::<()>(service)
        .oneshot(
            Request::builder()
                .uri("/api/auth/noop-middleware")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert!(exporter().get_finished_spans().unwrap().iter().all(|span| {
        span.name != "middleware /** noop-middleware"
            && span.name != "onRequest noop-middleware"
            && span.name != "onResponse noop-middleware"
    }));
}
