use super::{super::support, common, projection};
use crate::{AxumPluginRoute, commet::CommetPlugin};
use axum::{
    Extension,
    extract::Path,
    http::HeaderMap,
    response::Response,
    routing::{MethodRouter, get},
};
use std::sync::Arc;

pub(super) fn routes(layer: &impl Fn(MethodRouter) -> MethodRouter) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new("/commet/features", layer(get(list))),
        AxumPluginRoute::new("/commet/features/{code}", layer(get(get_feature))),
        AxumPluginRoute::new("/commet/features/{code}/check", layer(get(check))),
        AxumPluginRoute::new("/commet/features/{code}/can-use", layer(get(can_use))),
    ]
}

async fn list(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
) -> Response {
    let session = match common::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match plugin
        .options()
        .client
        .list_feature_access(&session.user.id.to_string())
        .await
    {
        Ok(value) => projection::json_field(value, "data"),
        Err(error) => common::provider_error(error, "Failed to list features"),
    }
}

async fn get_feature(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Response {
    let session = match common::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match plugin
        .options()
        .client
        .get_feature_access(&session.user.id.to_string(), &code)
        .await
    {
        Ok(value) => support::json(value),
        Err(error) => common::provider_error(error, "Failed to get feature"),
    }
}

async fn check(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Response {
    check_inner(service, plugin, headers, code, "Failed to check feature").await
}

async fn can_use(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Response {
    check_inner(
        service,
        plugin,
        headers,
        code,
        "Failed to check feature usage",
    )
    .await
}

async fn check_inner(
    service: Arc<crate::AuthService>,
    plugin: CommetPlugin,
    headers: HeaderMap,
    code: String,
    failure: &'static str,
) -> Response {
    let session = match common::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match plugin
        .options()
        .client
        .check_usage(&session.user.id.to_string(), &code)
        .await
    {
        Ok(value) => support::json(value),
        Err(error) => common::provider_error(error, failure),
    }
}
