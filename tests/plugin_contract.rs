use async_trait::async_trait;
use axum::{
    Json,
    body::Body,
    extract::Request,
    http::{Request as HttpRequest, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{MethodRouter, get},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AfterAuthEvent, AuthConfig, AuthError, AuthPlugin, AuthService, AxumPluginRoute,
    BeforeAuthEvent, MemoryStore, NewPasswordUser, PluginClientMetadata, PluginDescriptor,
    PluginEndpoint, PluginHttpMethod, PluginMiddleware, PluginMigration,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

const ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Get,
    path: "/native-test/ping",
    client_method: "nativeTest.ping",
}];
const MIDDLEWARE: &[PluginMiddleware] = &[PluginMiddleware {
    id: "native-test-header",
}];
const MIGRATIONS: &[PluginMigration] = &[PluginMigration {
    id: "create-records",
    description: "native test records",
    sql: "CREATE TABLE IF NOT EXISTS lucid_auth_native_test (id TEXT PRIMARY KEY)",
}];

struct TestPlugin {
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl AuthPlugin for TestPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        descriptor("native-test", &[], &[], ENDPOINTS)
    }

    fn migrations(&self) -> &'static [PluginMigration] {
        MIGRATIONS
    }

    async fn before(&self, event: &BeforeAuthEvent) -> Result<(), AuthError> {
        assert!(matches!(event, BeforeAuthEvent::SessionCreate { .. }));
        self.events.lock().await.push("before-session");
        Ok(())
    }

    async fn after(&self, event: &AfterAuthEvent) {
        assert!(matches!(event, AfterAuthEvent::SessionCreated { .. }));
        self.events.lock().await.push("after-session");
    }

    fn routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        vec![AxumPluginRoute::new("/native-test/ping", get(ping))]
    }

    fn middleware(&self, route: MethodRouter, _service: Arc<AuthService>) -> MethodRouter {
        route.layer(middleware::from_fn(add_plugin_header))
    }
}

async fn ping() -> Json<Value> {
    Json(json!({ "plugin": "native-test" }))
}

async fn add_plugin_header(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("x-native-plugin", "native-test".parse().unwrap());
    response
}

#[tokio::test]
async fn plugin_contributes_route_middleware_hooks_migration_and_client_metadata() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::new([92_u8; 32]).unwrap();
    config
        .add_plugin(TestPlugin {
            events: events.clone(),
        })
        .unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    service
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap();
    assert_eq!(
        events.lock().await.as_slice(),
        &["before-session", "after-session"]
    );

    let metadata = service.plugin_metadata()[0];
    assert_eq!(metadata.id, "native-test");
    assert_eq!(metadata.client.unwrap().factory, "nativeTestClient");
    let migrations = service.plugin_migrations();
    assert_eq!(migrations[0].plugin_id, "native-test");
    assert_eq!(migrations[0].migration.id, "create-records");

    let response = lucid_auth::axum::router(service)
        .oneshot(
            HttpRequest::get("/api/auth/native-test/ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-native-plugin"], "native-test");
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body, json!({ "plugin": "native-test" }));
}

struct MetadataPlugin(PluginDescriptor);

#[async_trait]
impl AuthPlugin for MetadataPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        self.0
    }
}

struct RejectingPlugin;

#[async_trait]
impl AuthPlugin for RejectingPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        descriptor("rejecting", &[], &[], &[])
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Err(AuthError::InvalidConfiguration(
            "rejecting plugin configuration".into(),
        ))
    }
}

#[test]
fn registry_orders_dependencies_and_rejects_missing_conflicting_or_core_routes() {
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([93_u8; 32]).unwrap();
    config
        .add_plugin(MetadataPlugin(descriptor("dependent", &["base"], &[], &[])))
        .unwrap();
    config
        .add_plugin(MetadataPlugin(descriptor("base", &[], &[], &[])))
        .unwrap();
    let service = AuthService::try_new(store.clone(), config).unwrap();
    assert_eq!(
        service
            .plugin_metadata()
            .iter()
            .map(|plugin| plugin.id)
            .collect::<Vec<_>>(),
        ["base", "dependent"]
    );

    let invalid = |plugins: Vec<PluginDescriptor>| {
        let mut config = AuthConfig::new([94_u8; 32]).unwrap();
        for plugin in plugins {
            config.add_plugin(MetadataPlugin(plugin)).unwrap();
        }
        AuthService::try_new(store.clone(), config)
            .err()
            .expect("invalid plugin registry")
    };
    assert!(matches!(
        invalid(vec![descriptor("missing", &["absent"], &[], &[])]),
        AuthError::InvalidConfiguration(_)
    ));
    assert!(matches!(
        invalid(vec![
            descriptor("cycle-a", &["cycle-b"], &[], &[]),
            descriptor("cycle-b", &["cycle-a"], &[], &[]),
        ]),
        AuthError::InvalidConfiguration(_)
    ));
    assert!(matches!(
        invalid(vec![
            descriptor("left", &[], &["right"], &[]),
            descriptor("right", &[], &[], &[]),
        ]),
        AuthError::InvalidConfiguration(_)
    ));
    const CORE_COLLISION: &[PluginEndpoint] = &[PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: "/get-session",
        client_method: "collision.getSession",
    }];
    assert!(matches!(
        invalid(vec![descriptor("collision", &[], &[], CORE_COLLISION)]),
        AuthError::InvalidConfiguration(_)
    ));

    let mut rejected = AuthConfig::new([95_u8; 32]).unwrap();
    rejected.add_plugin(RejectingPlugin).unwrap();
    assert!(matches!(
        AuthService::try_new(store, rejected),
        Err(AuthError::InvalidConfiguration(_))
    ));
}

fn descriptor(
    id: &'static str,
    dependencies: &'static [&'static str],
    conflicts: &'static [&'static str],
    endpoints: &'static [PluginEndpoint],
) -> PluginDescriptor {
    PluginDescriptor {
        id,
        display_name: id,
        version: "1.0.0",
        dependencies,
        conflicts,
        endpoints,
        cookies: &[],
        rate_limits: &[],
        middleware: if id == "native-test" { MIDDLEWARE } else { &[] },
        client: (id == "native-test").then(|| {
            PluginClientMetadata::current(
                "@lucid-auth/native-test",
                "@lucid-auth/native-test/client",
                "nativeTestClient",
            )
        }),
    }
}
