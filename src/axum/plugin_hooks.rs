use crate::{AuthService, PluginRequestContext};
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
        request = match plugin.on_request(&service, request).await {
            Ok(request) => request,
            Err(response) => return response,
        };
    }
    next.run(request).await
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
    };
    let mut response = next.run(request).await;
    for plugin in service.plugins().plugins() {
        response = plugin.after_response(&service, &context, response).await;
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
