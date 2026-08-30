use super::{auth, route, route_error};
use crate::{AuthService, AxumPluginRoute, DashAdapterAction, DashPlugin};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::Value;
use std::sync::Arc;

pub(super) fn routes(plugin: Arc<DashPlugin>) -> Vec<AxumPluginRoute> {
    vec![route(
        "/dash/execute-adapter",
        post(execute).layer(Extension(plugin)),
    )]
}

async fn execute(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(action): Json<DashAdapterAction>,
) -> Response {
    if let Err(response) = auth::regular::<Value>(&plugin, &headers).await {
        return response;
    }
    match service.dash_execute_adapter(action).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => route_error(error),
    }
}
