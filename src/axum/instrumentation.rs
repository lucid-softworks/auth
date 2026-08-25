use crate::{
    AuthService, PluginHttpMethod,
    instrumentation::{
        ATTR_CONTEXT, ATTR_HOOK_TYPE, ATTR_HTTP_ROUTE, EndpointSpanMetadata, SpanAttribute,
        with_http_handler_span, with_span_async,
    },
};
use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

pub(super) fn plugin_middleware(
    route: axum::routing::MethodRouter,
    path: &str,
    plugin_id: &'static str,
    contributed: bool,
) -> axum::routing::MethodRouter {
    if !contributed {
        return route;
    }
    let path = path.to_owned();
    route.layer(axum::middleware::from_fn(move |request: Request, next: Next| {
        let path = path.clone();
        async move {
            with_span_async(
                format!("middleware {path} {plugin_id}"),
                [
                    SpanAttribute::string(ATTR_HOOK_TYPE, "middleware"),
                    SpanAttribute::string(ATTR_HTTP_ROUTE, path.clone()),
                    SpanAttribute::string(ATTR_CONTEXT, format!("plugin:{plugin_id}")),
                ],
                next.run(request),
            )
            .await
        }
    }))
}

pub(super) async fn endpoint(
    State(service): State<Arc<AuthService>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .map(|path| relative_route(path, service.base_path()))
        .unwrap_or_else(|| "/:virtual".into());
    let operation_id = plugin_method(&method)
        .map(|method| service.plugins().endpoint_operation_id(method, &route))
        .unwrap_or_else(|| route.clone());
    let metadata = EndpointSpanMetadata::new(method, route, operation_id);
    let (dispatch_name, dispatch_attributes) = metadata.dispatch_span();
    with_span_async(dispatch_name, dispatch_attributes, async {
        let (handler_name, handler_attributes) = metadata.handler_span();
        with_http_handler_span(handler_name, handler_attributes, next.run(request)).await
    })
    .await
}

fn relative_route(path: &str, base_path: &str) -> String {
    let base = base_path.trim_end_matches('/');
    if path == base {
        return "/".into();
    }
    path.strip_prefix(base)
        .filter(|relative| relative.starts_with('/'))
        .unwrap_or(path)
        .to_owned()
}

fn plugin_method(method: &str) -> Option<PluginHttpMethod> {
    match method {
        "GET" => Some(PluginHttpMethod::Get),
        "POST" => Some(PluginHttpMethod::Post),
        "PUT" => Some(PluginHttpMethod::Put),
        "PATCH" => Some(PluginHttpMethod::Patch),
        "DELETE" => Some(PluginHttpMethod::Delete),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_only_the_configured_base_path() {
        assert_eq!(
            relative_route("/api/auth/callback/:id", "/api/auth"),
            "/callback/:id"
        );
        assert_eq!(
            relative_route("/.well-known/openid", "/api/auth"),
            "/.well-known/openid"
        );
    }

}
