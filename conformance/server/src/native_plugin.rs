use async_trait::async_trait;
use axum::{
    Json,
    extract::Request,
    http::HeaderValue,
    middleware::{self, Next},
    response::Response,
    routing::{MethodRouter, get},
};
use lucid_auth::{
    AuthPlugin, AuthService, AxumPluginRoute, PluginClientMetadata, PluginDescriptor,
    PluginEndpoint, PluginHttpMethod, PluginMiddleware, PluginMigration, PluginRateLimit,
    protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
};
use serde_json::json;
use std::sync::Arc;

pub(crate) struct ConformancePlugin;

const ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Get,
    path: "/native-plugin/ping",
    client_method: "nativePlugin.ping",
}];
const MIDDLEWARE: &[PluginMiddleware] = &[PluginMiddleware {
    id: "conformance-header",
}];
const RATE_LIMITS: &[PluginRateLimit] = &[PluginRateLimit {
    path: "/native-plugin/ping",
    window_seconds: 60,
    max_requests: 60,
}];
const MIGRATIONS: &[PluginMigration] = &[PluginMigration {
    id: "create-pings",
    description: "conformance plugin pings",
    sql: "CREATE TABLE IF NOT EXISTS lucid_auth_conformance_pings (id TEXT PRIMARY KEY)",
}];

#[async_trait]
impl AuthPlugin for ConformancePlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "conformance",
            display_name: "Native conformance plugin",
            version: "1.0.0",
            dependencies: &[],
            conflicts: &[],
            endpoints: ENDPOINTS,
            cookies: &[],
            rate_limits: RATE_LIMITS,
            middleware: MIDDLEWARE,
            client: Some(PluginClientMetadata::current(
                "lucid-auth-conformance",
                "./native-plugin-client.mjs",
                "nativePluginClient",
            )),
        }
    }

    fn migrations(&self) -> &'static [PluginMigration] {
        MIGRATIONS
    }

    fn routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        vec![AxumPluginRoute::new(
            "/native-plugin/ping",
            get(plugin_ping),
        )]
    }

    fn middleware(&self, route: MethodRouter, _service: Arc<AuthService>) -> MethodRouter {
        route.layer(middleware::from_fn(mark_response))
    }
}

async fn plugin_ping() -> Json<serde_json::Value> {
    Json(json!({
        "plugin": "conformance",
        "betterAuth": COMPATIBLE_BETTER_AUTH_VERSION,
    }))
}

async fn mark_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("x-native-plugin", HeaderValue::from_static("conformance"));
    response
}
