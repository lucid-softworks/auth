use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Request, StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, BearerConfig, BearerPlugin, DatabaseModel, MemoryStore,
    PluginDescriptor, PluginRequestContext,
};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const DEFAULT_COOKIE: &str = "better-auth.session_token";

struct Fixture {
    app: Router,
    service: Arc<AuthService>,
    origin: String,
}

struct IssuedSession {
    cookie: String,
    signed: String,
    opaque: String,
}

fn fixture(bearer: BearerConfig, configure: impl FnOnce(&mut AuthConfig)) -> Fixture {
    let mut config = AuthConfig::new([157_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.email_and_password.enabled = true;
    configure(&mut config);
    config.add_plugin(BearerPlugin::new(bearer)).unwrap();
    let origin = config.base_url().unwrap().origin().ascii_serialization();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        service,
        origin,
    }
}

async fn signup(fixture: &Fixture, email: &str, cookie_name: &str) -> IssuedSession {
    let response = signup_response(&fixture.app, &fixture.origin, email).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{cookie_name}=")))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let signed = response.headers()["set-auth-token"]
        .to_str()
        .unwrap()
        .to_owned();
    let opaque = signed.split('.').next().unwrap().to_owned();
    IssuedSession {
        cookie,
        signed,
        opaque,
    }
}

async fn signup_response(app: &Router, origin: &str, email: &str) -> Response {
    app.clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::ORIGIN, origin)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "Bearer User",
                        "email": email,
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn session(
    app: &Router,
    authorization: Option<&str>,
    cookie: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::get("/api/auth/get-session");
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (status, body)
}

async fn update_user(app: &Router, headers: &[(&str, &str)], name: &str) -> Response {
    let mut request =
        Request::post("/api/auth/update-user").header(header::CONTENT_TYPE, "application/json");
    for &(key, value) in headers {
        request = request.header(key, value);
    }
    app.clone()
        .oneshot(
            request
                .body(Body::from(json!({ "name": name }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn assert_session_email(value: &Value, email: &str) {
    assert_eq!(value["user"]["email"], email);
}

#[tokio::test]
async fn plugin_is_optional_and_contributes_only_a_server_hook() {
    let baseline = AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([158_u8; 32]).unwrap(),
    );
    assert!(baseline.plugin_metadata().is_empty());

    let fixture = fixture(BearerConfig::default(), |_| {});
    let descriptor = fixture
        .service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "bearer")
        .unwrap();
    assert!(descriptor.endpoints.is_empty());
    assert!(descriptor.cookies.is_empty() && descriptor.rate_limits.is_empty());
    assert!(descriptor.dependencies.is_empty());
    assert!(descriptor.client.is_none());
    assert!(fixture.service.plugin_migrations().is_empty());
    for model in [
        DatabaseModel::User,
        DatabaseModel::Session,
        DatabaseModel::Account,
        DatabaseModel::Verification,
    ] {
        assert_eq!(
            fixture.service.database_schema_fields(model).len(),
            baseline.database_schema_fields(model).len()
        );
    }
}

#[tokio::test]
async fn raw_signed_percent_encoded_and_scheme_spacing_match_upstream() {
    let fixture = fixture(BearerConfig::default(), |_| {});
    let issued = signup(&fixture, "forms@example.com", DEFAULT_COOKIE).await;
    let encoded = utf8_percent_encode(&issued.signed, NON_ALPHANUMERIC)
        .to_string()
        .replace("%2E", ".");
    for authorization in [
        format!("Bearer {}", issued.opaque),
        format!("bearer {}", issued.signed),
        format!("BeArEr {encoded}"),
        format!("BEARER      {}  ", issued.signed),
    ] {
        let (status, body) = session(&fixture.app, Some(&authorization), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_session_email(&body, "forms@example.com");
    }

    for authorization in [
        format!("Bearer{}", issued.opaque),
        format!("Bearer\t{}", issued.opaque),
        format!(" Bearer {}", issued.opaque),
        format!("Basic {}", issued.opaque),
        "Bearer    ".into(),
    ] {
        let (status, body) = session(&fixture.app, Some(&authorization), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, Value::Null);
    }
}

#[tokio::test]
async fn require_signature_and_cookie_precedence_match_upstream() {
    let strict_config = BearerConfig {
        require_signature: true,
    };
    let strict = fixture(strict_config, |_| {});
    let strict_session = signup(&strict, "strict@example.com", DEFAULT_COOKIE).await;
    assert_eq!(
        session(
            &strict.app,
            Some(&format!("Bearer {}", strict_session.opaque)),
            None,
        )
        .await
        .1,
        Value::Null
    );
    assert_session_email(
        &session(
            &strict.app,
            Some(&format!("Bearer {}", strict_session.signed)),
            None,
        )
        .await
        .1,
        "strict@example.com",
    );

    let fixture = fixture(BearerConfig::default(), |_| {});
    let first = signup(&fixture, "first@example.com", DEFAULT_COOKIE).await;
    let second = signup(&fixture, "second@example.com", DEFAULT_COOKIE).await;
    let (_, body) = session(
        &fixture.app,
        Some(&format!("Bearer {}", second.signed)),
        Some(&first.cookie),
    )
    .await;
    assert_session_email(&body, "second@example.com");

    let (_, body) = session(
        &fixture.app,
        Some("Bearer invalid.invalid"),
        Some(&first.cookie),
    )
    .await;
    assert_session_email(&body, "first@example.com");

    let (_, body) = session(
        &fixture.app,
        Some("Bearer missing-opaque-session"),
        Some(&first.cookie),
    )
    .await;
    assert_eq!(body, Value::Null);

    let mut request = Request::get("/api/auth/get-session")
        .header(header::COOKIE, &first.cookie)
        .body(Body::empty())
        .unwrap();
    request.headers_mut().append(
        header::AUTHORIZATION,
        format!("Bearer {}", second.signed).parse().unwrap(),
    );
    request
        .headers_mut()
        .append(header::AUTHORIZATION, "Bearer combined".parse().unwrap());
    let response = fixture.app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_session_email(&body, "first@example.com");
}

#[tokio::test]
async fn bearer_only_post_bypasses_browser_origin_checks_without_adding_challenges() {
    let fixture = fixture(BearerConfig::default(), |_| {});
    let issued = signup(&fixture, "post@example.com", DEFAULT_COOKIE).await;
    let opaque = format!("Bearer {}", issued.opaque);
    let response = update_user(
        &fixture.app,
        &[("authorization", &opaque)],
        "Bearer Updated",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let signed = format!("Bearer {}", issued.signed);
    let cross_site = update_user(
        &fixture.app,
        &[
            ("authorization", &signed),
            ("origin", "https://evil.example"),
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-dest", "document"),
        ],
        "Cross-Site Bearer",
    )
    .await;
    assert_eq!(cross_site.status(), StatusCode::OK);

    let cookie_only = update_user(&fixture.app, &[("cookie", &issued.cookie)], "Blocked").await;
    assert_eq!(cookie_only.status(), StatusCode::FORBIDDEN);

    let invalid = update_user(
        &fixture.app,
        &[("authorization", "Bearer invalid.invalid")],
        "Missing",
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    assert!(!invalid.headers().contains_key(header::WWW_AUTHENTICATE));
    assert!(!invalid.headers().contains_key(header::AUTHORIZATION));
}

struct ResponseHeadersPlugin;

#[async_trait]
impl AuthPlugin for ResponseHeadersPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "bearer-response-fixture",
            display_name: "Bearer response fixture",
            version: "1.7.1",
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    async fn after_response(
        &self,
        _service: &AuthService,
        request: &PluginRequestContext,
        mut response: Response,
    ) -> Response {
        if request.path == "/sign-up/email" {
            response.headers_mut().insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                HeaderValue::from_static("X-First, Set-Auth-Token"),
            );
            response
                .headers_mut()
                .insert("set-auth-token", HeaderValue::from_static("replaced"));
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_static("better-auth.session_token=last.value; Path=/"),
            );
        }
        response
    }
}

#[tokio::test]
async fn issued_and_cleared_cookies_drive_auth_token_and_cors_headers() {
    let mut config = AuthConfig::new([159_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.email_and_password.enabled = true;
    config.add_plugin(ResponseHeadersPlugin).unwrap();
    config.add_plugin(BearerPlugin::default()).unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let app = lucid_auth::axum::router(service);
    let response = signup_response(&app, "http://localhost", "response@example.com").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["set-auth-token"], "last.value");
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
        "X-First, Set-Auth-Token, set-auth-token"
    );
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["user"]["email"], "response@example.com");

    let fixture = fixture(BearerConfig::default(), |_| {});
    let issued = signup(&fixture, "clear@example.com", DEFAULT_COOKIE).await;
    let signed_cookie_value = issued.cookie.split_once('=').unwrap().1;
    assert_eq!(
        issued.signed,
        percent_decode_str(signed_cookie_value)
            .decode_utf8()
            .unwrap()
    );
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-out")
                .header(header::ORIGIN, &fixture.origin)
                .header(header::COOKIE, &issued.cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("set-auth-token"));
    assert!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| {
                let value = value.to_str().unwrap();
                value.starts_with("better-auth.session_token=") && value.contains("Max-Age=0")
            })
    );
}

#[tokio::test]
async fn custom_secure_session_cookie_names_are_used_in_both_directions() {
    let fixture = fixture(BearerConfig::default(), |config| {
        config.set_base_url("https://auth.example.com").unwrap();
        config.cookies.session_token.name = Some("custom.session".into());
    });
    let issued = signup(&fixture, "custom@example.com", "__Secure-custom.session").await;
    assert_session_email(
        &session(
            &fixture.app,
            Some(&format!("Bearer {}", issued.signed)),
            None,
        )
        .await
        .1,
        "custom@example.com",
    );
}
