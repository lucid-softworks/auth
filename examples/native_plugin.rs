use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Request,
    middleware::{self, Next},
    response::Response,
    routing::{MethodRouter, get},
};
use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, AxumPluginRoute, MemoryStore, PluginClientMetadata,
    PluginCookie, PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginMiddleware,
    PluginMigration, PluginRateLimit,
};
use serde_json::json;
use std::sync::Arc;

struct GreetingPlugin;

const ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Get,
    path: "/native-example/greeting",
    client_method: "greeting.message",
}];
const COOKIES: &[PluginCookie] = &[PluginCookie {
    name: "example.greeting",
}];
const RATE_LIMITS: &[PluginRateLimit] = &[PluginRateLimit {
    path: "/native-example/greeting",
    window: 60,
    max: 30,
}];
const MIDDLEWARE: &[PluginMiddleware] = &[PluginMiddleware {
    id: "example-response-header",
}];
const MIGRATIONS: &[PluginMigration] = &[PluginMigration {
    id: "create-greetings",
    description: "example greeting records",
    sql: "CREATE TABLE IF NOT EXISTS lucid_auth_example_greetings (message TEXT PRIMARY KEY)",
}];

#[async_trait]
impl AuthPlugin for GreetingPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "greeting",
            display_name: "Greeting example",
            version: "1.0.0",
            dependencies: &[],
            conflicts: &[],
            endpoints: ENDPOINTS,
            cookies: COOKIES,
            rate_limits: RATE_LIMITS,
            middleware: MIDDLEWARE,
            client: Some(PluginClientMetadata::current(
                "@example/lucid-auth-greeting",
                "@example/lucid-auth-greeting/client",
                "greetingClient",
            )),
        }
    }

    fn migrations(&self) -> &'static [PluginMigration] {
        MIGRATIONS
    }

    fn routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        vec![AxumPluginRoute::new(
            "/native-example/greeting",
            get(greeting),
        )]
    }

    fn middleware(&self, route: MethodRouter, _service: Arc<AuthService>) -> MethodRouter {
        route.layer(middleware::from_fn(mark_example_response))
    }
}

async fn greeting() -> Json<serde_json::Value> {
    Json(json!({ "message": "hello from a native plugin" }))
}

async fn mark_example_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("x-native-plugin", "greeting".parse().unwrap());
    response
}

fn main() {
    let mut config = AuthConfig::new([91_u8; 32]).expect("valid secret");
    config
        .add_plugin(GreetingPlugin)
        .expect("unique native plugin");
    let service = Arc::new(
        AuthService::try_new(Arc::new(MemoryStore::default()), config)
            .expect("valid plugin dependency graph"),
    );
    let _router: Router = lucid_auth::axum::router(service.clone());
    println!(
        "enabled {} with {} migration",
        service.plugin_metadata()[0].display_name,
        service.plugin_migrations().len()
    );
}
