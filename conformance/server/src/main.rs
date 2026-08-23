use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::{Path, Request},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
use chrono::{Duration, Utc};
use lucid_auth::{
    Assurance, AuthConfig, AuthPlugin, AuthService, AuthSession, AuthStore, AxumPluginRoute,
    MemoryStore, NewPasswordUser, PasskeyConfig, PluginClientMetadata, PluginDescriptor,
    PluginEndpoint, PluginHttpMethod, PluginMiddleware, PluginMigration, PluginRateLimit,
    StoredPasskey, protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{io::Write, net::SocketAddr, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
struct Fixture {
    service: Arc<AuthService>,
    store: Arc<MemoryStore>,
    owner_id: Uuid,
}

struct ConformancePlugin;

const PLUGIN_ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Get,
    path: "/native-plugin/ping",
    client_method: "nativePlugin.ping",
}];
const PLUGIN_MIDDLEWARE: &[PluginMiddleware] = &[PluginMiddleware {
    id: "conformance-header",
}];
const PLUGIN_RATE_LIMITS: &[PluginRateLimit] = &[PluginRateLimit {
    path: "/native-plugin/ping",
    window_seconds: 60,
    max_requests: 60,
}];
const PLUGIN_MIGRATIONS: &[PluginMigration] = &[PluginMigration {
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
            endpoints: PLUGIN_ENDPOINTS,
            cookies: &[],
            rate_limits: PLUGIN_RATE_LIMITS,
            middleware: PLUGIN_MIDDLEWARE,
            client: Some(PluginClientMetadata::current(
                "lucid-auth-conformance",
                "./native-plugin-client.mjs",
                "nativePluginClient",
            )),
        }
    }

    fn migrations(&self) -> &'static [PluginMigration] {
        PLUGIN_MIGRATIONS
    }

    fn routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        vec![AxumPluginRoute::new(
            "/native-plugin/ping",
            get(plugin_ping),
        )]
    }

    fn middleware(&self, route: MethodRouter, _service: Arc<AuthService>) -> MethodRouter {
        route.layer(middleware::from_fn(mark_plugin_response))
    }
}

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind conformance server");
    let port = listener.local_addr().expect("fixture address").port();
    let origin = format!("http://localhost:{port}");
    let fixture = fixture(&origin).await;
    let app = Router::new()
        .route("/__conformance__/version", get(compatible_version))
        .route("/__conformance__/plugins", get(plugin_metadata))
        .route(
            "/__conformance__/session/{assurance}",
            post(create_fixture_session),
        )
        .merge(lucid_auth::axum::router(fixture.service.clone()))
        .layer(Extension(fixture));

    println!("LUCID_AUTH_CONFORMANCE_URL={origin}");
    std::io::stdout().flush().expect("flush fixture address");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("serve conformance fixture");
}

async fn compatible_version() -> Json<serde_json::Value> {
    Json(json!({ "betterAuth": COMPATIBLE_BETTER_AUTH_VERSION }))
}

async fn plugin_metadata(Extension(fixture): Extension<Fixture>) -> Json<Vec<PluginDescriptor>> {
    Json(fixture.service.plugin_metadata().to_vec())
}

async fn plugin_ping() -> Json<serde_json::Value> {
    Json(json!({
        "plugin": "conformance",
        "betterAuth": COMPATIBLE_BETTER_AUTH_VERSION,
    }))
}

async fn mark_plugin_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("x-native-plugin", HeaderValue::from_static("conformance"));
    response
}

async fn fixture(origin: &str) -> Fixture {
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([82_u8; 32]).expect("fixture secret");
    config.allow_anonymous = true;
    config.email_and_password.enabled = true;
    config
        .set_base_url(origin)
        .expect("localhost fixture origin");
    config.passkeys = Some(PasskeyConfig {
        rp_id: "localhost".into(),
        rp_origin: origin.into(),
        rp_name: "lucid-auth conformance".into(),
    });
    config
        .add_plugin(ConformancePlugin)
        .expect("unique conformance plugin");
    let service = Arc::new(
        AuthService::try_new(store.clone(), config).expect("valid conformance plugin registry"),
    );
    let owner = service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: Some("luna@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .expect("provision fixture owner");
    Fixture {
        service,
        store,
        owner_id: owner.id,
    }
}

async fn create_fixture_session(
    Extension(fixture): Extension<Fixture>,
    Path(assurance): Path<String>,
) -> Response {
    let assurance = match assurance.as_str() {
        "strong" => Assurance::PasswordAndPasskey,
        "pending" => Assurance::PasswordPendingPasskey,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let token = Uuid::new_v4().to_string();
    let now = Utc::now();
    if assurance == Assurance::PasswordAndPasskey
        && fixture
            .store
            .list_passkeys(fixture.owner_id)
            .await
            .expect("list fixture passkeys")
            .is_empty()
    {
        fixture
            .store
            .save_passkey(StoredPasskey {
                id: Uuid::new_v4(),
                user_id: fixture.owner_id,
                name: Some("Conformance key".into()),
                credential_id: "conformance-credential".into(),
                credential: json!({}),
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("persist fixture passkey");
    }
    fixture
        .store
        .create_session(AuthSession {
            id: Uuid::new_v4(),
            user_id: fixture.owner_id,
            token_hash: hex::encode(Sha256::digest(token.as_bytes())),
            actor_user_id: None,
            guest_grant_id: None,
            assurance,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: Some("official Better Auth client conformance".into()),
        })
        .await
        .expect("persist fixture session");
    let cookie = format!(
        "better-auth.session_token={}; Path=/; HttpOnly; SameSite=Lax",
        fixture.service.signed_cookie_value(&token)
    );
    let mut response = Json(json!({ "status": true })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("fixture cookie header"),
    );
    response
}
