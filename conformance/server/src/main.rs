use axum::{
    Extension, Json, Router,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use lucid_auth::{
    AdditionalField, AdditionalFieldType, AdminConfig, AdminPlugin, AdminRole,
    ApiKeyConfiguration, ApiKeyPlugin, AuthConfig, AuthService,
    MagicLinkConfig, MagicLinkEmail, MagicLinkPlugin, MemoryStore, MemoryTwoFactorStore,
    NewPasswordUser, OtpConfig, PasskeyConfig, PasskeyPlugin, PasswordResetEmail,
    TotpConfig, TwoFactorConfig, TwoFactorOtp, TwoFactorPlugin, UsernamePlugin, VerificationEmail,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::{io::Write, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

mod email;
mod metadata;
mod native_plugin;
mod session_fixture;
mod social_provider;

use email::{
    ConformanceEmailSender, ConformanceMagicLinkSender, ConformanceMessages,
    ConformanceOtpSender,
};
use native_plugin::ConformancePlugin;

#[derive(Clone)]
struct Fixture {
    pub(crate) service: Arc<AuthService>,
    pub(crate) store: Arc<MemoryStore>,
    pub(crate) owner_id: Uuid,
    verification_emails: Arc<Mutex<Vec<VerificationEmail>>>,
    password_reset_emails: Arc<Mutex<Vec<PasswordResetEmail>>>,
    magic_links: Arc<Mutex<Vec<MagicLinkEmail>>>,
    two_factor_otps: Arc<Mutex<Vec<TwoFactorOtp>>>,
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
        .route("/__conformance__/version", get(metadata::compatible_version))
        .route("/__conformance__/plugins", get(metadata::plugin_metadata))
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
            "/__conformance__/two-factor-otp/{email}",
            get(two_factor_otp),
        )
        .route(
            "/__conformance__/session/{authentication_method}",
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

async fn two_factor_otp(
    Extension(fixture): Extension<Fixture>,
    Path(email): Path<String>,
) -> Response {
    let sent = fixture.two_factor_otps.lock().await;
    match sent
        .iter()
        .rev()
        .find(|message| message.user.email == email)
    {
        Some(message) => Json(json!({ "code": message.code })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn fixture(origin: &str) -> Fixture {
    let store = Arc::new(MemoryStore::default());
    let messages = ConformanceMessages::default();
    let config = conformance_config(origin, &messages);
    let service = Arc::new(
        AuthService::try_new(store.clone(), config).expect("valid conformance plugin registry"),
    );
    let owner = service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: Some("luna@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "admin".into(),
        })
        .await
        .expect("provision fixture owner");
    Fixture {
        service,
        store,
        owner_id: owner.id,
        verification_emails: messages.verification_emails,
        password_reset_emails: messages.password_reset_emails,
        magic_links: messages.magic_links,
        two_factor_otps: messages.two_factor_otps,
    }
}

fn conformance_config(origin: &str, messages: &ConformanceMessages) -> AuthConfig {
    let mut config = AuthConfig::new([82_u8; 32]).expect("fixture secret");
    let mut admin = AdminConfig::default();
    admin.set_role("member", AdminRole::new());
    admin.set_role("viewer", AdminRole::new());
    config
        .add_plugin(AdminPlugin::new(admin))
        .expect("unique admin plugin");
    config.allow_anonymous = true;
    config.email_and_password.enabled = true;
    config.user.delete_user.enabled = true;
    config.user.change_email.enabled = true;
    config.user.additional_fields.insert(
        "timezone".into(),
        AdditionalField::new(AdditionalFieldType::String),
    );
    config.session.additional_fields.insert(
        "theme".into(),
        AdditionalField::new(AdditionalFieldType::String),
    );
    config.email_verification.sender = Some(Arc::new(ConformanceEmailSender {
        verification: messages.verification_emails.clone(),
        password_reset: messages.password_reset_emails.clone(),
    }));
    config.email_and_password.send_reset_password = Some(Arc::new(ConformanceEmailSender {
        verification: messages.verification_emails.clone(),
        password_reset: messages.password_reset_emails.clone(),
    }));
    config.email_and_password.revoke_sessions_on_password_reset = true;
    config.email_verification.auto_sign_in_after_verification = true;
    config
        .set_base_url(origin)
        .expect("localhost fixture origin");
    config
        .add_social_provider(social_provider::ConformanceSocialProvider)
        .expect("unique social provider");
    config
        .add_plugin(UsernamePlugin::default())
        .expect("unique username plugin");
    add_conformance_plugins(&mut config, origin, messages);
    config
}

fn add_conformance_plugins(config: &mut AuthConfig, origin: &str, messages: &ConformanceMessages) {
    config
        .add_plugin(PasskeyPlugin::new(PasskeyConfig {
            rp_id: Some("localhost".into()),
            rp_name: Some("lucid-auth conformance".into()),
            origins: Some(vec![origin.into()]),
            ..PasskeyConfig::default()
        }))
        .expect("unique passkey plugin");
    config
        .add_plugin(ApiKeyPlugin::new(ApiKeyConfiguration {
            enable_metadata: true,
            enable_session_for_api_keys: true,
            default_permissions: Some(BTreeMap::from([("documents".into(), vec!["read".into()])])),
            ..ApiKeyConfiguration::default()
        }))
        .expect("unique API-key plugin");
    config
        .add_plugin(ConformancePlugin)
        .expect("unique conformance plugin");
    config
        .add_plugin(MagicLinkPlugin::new(MagicLinkConfig::new(Arc::new(
            ConformanceMagicLinkSender {
                messages: messages.magic_links.clone(),
            },
        ))))
        .expect("unique magic-link plugin");
    config
        .add_plugin(TwoFactorPlugin::new(
            Arc::new(MemoryTwoFactorStore::default()),
            TwoFactorConfig {
                totp: TotpConfig {
                    period: chrono::Duration::seconds(1),
                    ..TotpConfig::default()
                },
                otp: Some(OtpConfig::new(Arc::new(ConformanceOtpSender {
                    messages: messages.two_factor_otps.clone(),
                }))),
                ..TwoFactorConfig::default()
            },
        ))
        .expect("unique two-factor plugin");
}
