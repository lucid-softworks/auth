use crate::{
    AuthService, PluginRequestContext,
    instrumentation::{
        ATTR_CONTEXT, ATTR_HOOK_TYPE, ATTR_HTTP_RESPONSE_STATUS_CODE, SpanAttribute,
        with_span_async,
    },
};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::{collections::BTreeMap, sync::Arc};

pub(super) async fn before_request(
    State(service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    for plugin in service.plugins().plugins() {
        if !plugin.contributes_on_request() {
            continue;
        }
        let id = plugin.descriptor().id;
        let result = with_span_async(
            format!("onRequest {id}"),
            [
                SpanAttribute::string(ATTR_HOOK_TYPE, "onRequest"),
                SpanAttribute::string(ATTR_CONTEXT, format!("plugin:{id}")),
            ],
            plugin.on_request(&service, request),
        )
        .await;
        request = match result {
            Ok(request) => request,
            Err(response) => return response,
        };
    }
    let captured_body = request
        .extensions()
        .get::<crate::plugin::CapturedPluginRequestBody>()
        .cloned();
    let mut response = next.run(request).await;
    if let Some(body) = captured_body {
        response.extensions_mut().insert(body);
    }
    response
}

pub(super) async fn after_response(
    State(service): State<Arc<AuthService>>,
    request: Request,
    next: Next,
) -> Response {
    let context = PluginRequestContext {
        method: request.method().to_string(),
        path: relative_path(request.uri().path(), service.base_path()),
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
        body: request
            .extensions()
            .get::<crate::plugin::CapturedPluginRequestBody>()
            .map(|body| body.0.clone()),
    };
    let mut response = next.run(request).await;
    for plugin in service.plugins().plugins() {
        if !plugin.contributes_on_response() {
            continue;
        }
        let id = plugin.descriptor().id;
        let status = i64::from(response.status().as_u16());
        response = with_span_async(
            format!("onResponse {id}"),
            [
                SpanAttribute::string(ATTR_HOOK_TYPE, "onResponse"),
                SpanAttribute::string(ATTR_CONTEXT, format!("plugin:{id}")),
                SpanAttribute::integer(ATTR_HTTP_RESPONSE_STATUS_CODE, status),
            ],
            plugin.after_response(&service, &context, response),
        )
        .await;
    }
    response
}

fn relative_path(path: &str, base_path: &str) -> String {
    let base = base_path.trim_end_matches('/');
    if path == base {
        return "/".into();
    }
    path.strip_prefix(base)
        .filter(|relative| relative.starts_with('/'))
        .unwrap_or(path)
        .to_owned()
}
