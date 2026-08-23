use axum::{
    Extension, Json, Router,
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use lucid_auth::{
    Assurance, AuthConfig, AuthService, AuthSession, AuthStore, MemoryStore, NewPasswordUser,
    PasskeyConfig, StoredPasskey, protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
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

async fn fixture(origin: &str) -> Fixture {
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([82_u8; 32]).expect("fixture secret");
    config.allow_anonymous = true;
    config
        .set_base_url(origin)
        .expect("localhost fixture origin");
    config.passkeys = Some(PasskeyConfig {
        rp_id: "localhost".into(),
        rp_origin: origin.into(),
        rp_name: "lucid-auth conformance".into(),
    });
    let service = Arc::new(AuthService::new(store.clone(), config));
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
