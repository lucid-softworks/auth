use axum::{
    Extension, Json, Router,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use lucid_auth::{
    AuthConfig, AuthService, MagicLinkConfig, MagicLinkEmail, MagicLinkPlugin, MemoryStore,
    NewPasswordUser, PasskeyConfig, PasswordResetEmail, PluginDescriptor, VerificationEmail,
    protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
};
use serde_json::json;
use std::{io::Write, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

mod email;
mod native_plugin;
mod session_fixture;

use email::{ConformanceEmailSender, ConformanceMagicLinkSender};
use native_plugin::ConformancePlugin;

#[derive(Clone)]
struct Fixture {
    service: Arc<AuthService>,
    pub(crate) store: Arc<MemoryStore>,
    pub(crate) owner_id: Uuid,
    verification_emails: Arc<Mutex<Vec<VerificationEmail>>>,
    password_reset_emails: Arc<Mutex<Vec<PasswordResetEmail>>>,
    magic_links: Arc<Mutex<Vec<MagicLinkEmail>>>,
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
            "/__conformance__/verification-token/{email}",
            get(verification_token),
        )
        .route(
            "/__conformance__/password-reset-token/{email}",
            get(password_reset_token),
        )
        .route(
            "/__conformance__/magic-link-token/{email}",
            get(magic_link_token),
        )
        .route(
            "/__conformance__/session/{assurance}",
            post(session_fixture::create),
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

async fn verification_token(
    Extension(fixture): Extension<Fixture>,
    Path(email): Path<String>,
) -> Response {
    let sent = fixture.verification_emails.lock().await;
    match sent
        .iter()
        .rev()
        .find(|message| message.user.email == email)
    {
        Some(message) => Json(json!({ "token": message.token })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn password_reset_token(
    Extension(fixture): Extension<Fixture>,
    Path(email): Path<String>,
) -> Response {
    let sent = fixture.password_reset_emails.lock().await;
    match sent
        .iter()
        .rev()
        .find(|message| message.user.email == email)
    {
        Some(message) => Json(json!({ "token": message.token })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn magic_link_token(
    Extension(fixture): Extension<Fixture>,
    Path(email): Path<String>,
) -> Response {
    let sent = fixture.magic_links.lock().await;
    match sent.iter().rev().find(|message| message.email == email) {
        Some(message) => Json(json!({ "token": message.token })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn fixture(origin: &str) -> Fixture {
    let store = Arc::new(MemoryStore::default());
    let verification_emails = Arc::new(Mutex::new(Vec::new()));
    let password_reset_emails = Arc::new(Mutex::new(Vec::new()));
    let magic_links = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::new([82_u8; 32]).expect("fixture secret");
    config.allow_anonymous = true;
    config.email_and_password.enabled = true;
    config.email_verification.sender = Some(Arc::new(ConformanceEmailSender {
        verification: verification_emails.clone(),
        password_reset: password_reset_emails.clone(),
    }));
    config.email_and_password.send_reset_password = Some(Arc::new(ConformanceEmailSender {
        verification: verification_emails.clone(),
        password_reset: password_reset_emails.clone(),
    }));
    config.email_and_password.revoke_sessions_on_password_reset = true;
    config.email_verification.auto_sign_in_after_verification = true;
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
    config
        .add_plugin(MagicLinkPlugin::new(MagicLinkConfig::new(Arc::new(
            ConformanceMagicLinkSender {
                messages: magic_links.clone(),
            },
        ))))
        .expect("unique magic-link plugin");
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
        verification_emails,
        password_reset_emails,
        magic_links,
    }
}
