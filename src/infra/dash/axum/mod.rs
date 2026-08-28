use super::DashPlugin;
use crate::{AuthError, AuthService, AxumPluginRoute};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use std::sync::Arc;

mod adapter;
mod analytics;
mod auth;
mod email;
mod input;
mod sessions;
mod users;

pub(super) fn routes(
    _service: Arc<AuthService>,
    plugin: DashPlugin,
) -> Vec<AxumPluginRoute> {
    let plugin = Arc::new(plugin);
    let mut routes = vec![
        route(
            "/dash/config",
            get(config).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/validate",
            get(validate).layer(Extension(plugin.clone())),
        ),
    ];
    routes.extend(users::routes(plugin.clone()));
    routes.extend(sessions::routes(plugin.clone()));
    routes.extend(analytics::routes(plugin.clone()));
    routes.extend(email::routes(plugin.clone()));
    routes.extend(adapter::routes(plugin));
    routes
}

fn route(path: &'static str, router: axum::routing::MethodRouter) -> AxumPluginRoute {
    AxumPluginRoute::new(path, router)
}

async fn config(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = auth::regular::<serde_json::Value>(&plugin, &headers).await {
        return response;
    }
    Json(service.dash_config_snapshot()).into_response()
}

async fn validate(
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    match plugin
        .verifier()
        .validate_authorization(auth::authorization(&headers))
        .await
    {
        Ok(_) => Json(json!({"valid": true})).into_response(),
        Err(_) => auth::unauthorized(),
    }
}

pub(super) fn route_error(error: AuthError) -> Response {
    match error {
        AuthError::NotFound => crate::axum::api_error(
            axum::http::StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "User not found",
        ),
        error => crate::axum::http::auth_error(error),
    }
}
