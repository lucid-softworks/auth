use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use chrono::Duration;
use data_encoding::BASE32_NOPAD;
use http_body_util::BodyExt;
use lucid_auth::{
    AccountLockoutConfig, AuthConfig, AuthError, AuthService, MemoryStore, MemoryTwoFactorStore,
    NewPasswordUser, OtpConfig, TotpConfig, TwoFactorConfig, TwoFactorOtp, TwoFactorOtpSender,
    TwoFactorPlugin, TwoFactorStore, UsernamePlugin,
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tower::ServiceExt;
use url::Url;

#[path = "two_factor_contract/lifecycle.rs"]
mod lifecycle;
#[path = "two_factor_contract/security.rs"]
mod security;

#[derive(Default)]
struct CapturingOtpSender {
    messages: Mutex<Vec<TwoFactorOtp>>,
}

#[async_trait]
impl TwoFactorOtpSender for CapturingOtpSender {
    async fn send(&self, otp: TwoFactorOtp) -> Result<(), AuthError> {
        self.messages.lock().await.push(otp);
        Ok(())
    }
}

struct Fixture {
    app: Router,
    service: Arc<AuthService>,
    factors: Arc<MemoryTwoFactorStore>,
    otps: Arc<CapturingOtpSender>,
}

async fn fixture(
    skip_verification_on_enable: bool,
    trust_device_ttl: Duration,
    max_failed_attempts: u32,
) -> Fixture {
    let factors = Arc::new(MemoryTwoFactorStore::default());
    let otps = Arc::new(CapturingOtpSender::default());
    let mut config = AuthConfig::new([88_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    config
        .add_plugin(TwoFactorPlugin::new(
            factors.clone(),
            TwoFactorConfig {
                issuer: Some("Example Co".into()),
                skip_verification_on_enable,
                trust_device_ttl,
                totp: TotpConfig {
                    period: Duration::seconds(1),
                    ..TotpConfig::default()
                },
                otp: Some(OtpConfig::new(otps.clone())),
                account_lockout: AccountLockoutConfig {
                    max_failed_attempts,
                    ..AccountLockoutConfig::default()
                },
                ..TwoFactorConfig::default()
            },
        ))
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: Some("luna@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        service,
        factors,
        otps,
    }
}

#[derive(Clone, Default)]
struct CookieJar(HashMap<String, String>);

impl CookieJar {
    fn header(&self) -> Option<String> {
        (!self.0.is_empty()).then(|| {
            self.0
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    fn absorb(&mut self, headers: &HeaderMap) {
        for value in headers.get_all(header::SET_COOKIE) {
            let value = value.to_str().unwrap();
            let mut parts = value.split(';');
            let (name, cookie_value) = parts.next().unwrap().split_once('=').unwrap();
            let removed = cookie_value.is_empty()
                || parts.any(|attribute| attribute.trim().eq_ignore_ascii_case("max-age=0"));
            if removed {
                self.0.remove(name);
            } else {
                self.0.insert(name.into(), cookie_value.into());
            }
        }
    }

    fn remove(&mut self, name: &str) {
        self.0.remove(name);
    }

    fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
}

async fn request(
    app: &Router,
    cookies: &mut CookieJar,
    path: &str,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::post(path)
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookies.header() {
        builder = builder.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    cookies.absorb(&headers);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

async fn sign_in(app: &Router, cookies: &mut CookieJar) -> (StatusCode, HeaderMap, Value) {
    request(
        app,
        cookies,
        "/api/auth/sign-in/username",
        json!({
            "username": "luna",
            "password": "correct horse battery staple"
        }),
    )
    .await
}

async fn enable_totp(
    fixture: &Fixture,
    cookies: &mut CookieJar,
) -> (String, String, Vec<String>, Value) {
    let (status, _, signed_in) = sign_in(&fixture.app, cookies).await;
    assert_eq!(status, StatusCode::OK, "{signed_in}");
    assert_eq!(signed_in["user"]["twoFactorEnabled"], false);
    let user_id = signed_in["user"]["id"].as_str().unwrap().to_owned();
    let (status, _, enabled) = request(
        &fixture.app,
        cookies,
        "/api/auth/two-factor/enable",
        json!({
            "password": "correct horse battery staple",
            "method": "totp",
            "issuer": "lucid-auth conformance"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    let uri = Url::parse(enabled["totpURI"].as_str().unwrap()).unwrap();
    let encoded_secret = uri
        .query_pairs()
        .find_map(|(key, value)| (key == "secret").then(|| value.into_owned()))
        .unwrap();
    let secret =
        String::from_utf8(BASE32_NOPAD.decode(encoded_secret.as_bytes()).unwrap()).unwrap();
    let backup_codes = enabled["backupCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_owned())
        .collect();
    (user_id, secret, backup_codes, enabled)
}
