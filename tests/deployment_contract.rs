use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::{
    AuthConfig, AuthService, MemoryStore, NewPasswordUser, PasskeyConfig, PasskeyPlugin, SameSite,
    UsernamePlugin,
};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

async fn application(configure: impl FnOnce(&mut AuthConfig)) -> Router {
    let mut config = AuthConfig::new([83_u8; 32]).unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    configure(&mut config);
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
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
    lucid_auth::axum::router(service)
}

fn sign_in(path: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "username": "luna", "password": "password" }).to_string(),
        ))
        .unwrap()
}

fn cookie_scope(cookie: &str) -> Vec<&str> {
    cookie
        .split("; ")
        .skip(1)
        .filter(|attribute| !attribute.starts_with("Max-Age="))
        .collect()
}

#[tokio::test]
async fn custom_base_path_and_https_cookie_policy_round_trip() {
    let app = application(|config| {
        config
            .set_base_url("https://auth.example.com/custom-auth")
            .unwrap();
        config.cookies.prefix = "lucid".into();
        config.cookies.session_token.name = Some("session".into());
        config.cookies.default_attributes.same_site = Some(SameSite::None);
        config
            .cookies
            .set_cross_subdomain(true, Some(".example.com".into()));
    })
    .await;

    let response = app
        .clone()
        .oneshot(sign_in("/custom-auth/sign-in/username"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(created.starts_with("__Secure-session="));
    assert!(created.contains("; HttpOnly; SameSite=None; Path=/; Domain=.example.com"));
    assert!(created.contains("; Max-Age=604800; Secure"));
    let request_cookie = created.split(';').next().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::post("/custom-auth/sign-out")
                .header(header::COOKIE, request_cookie)
                .header(header::ORIGIN, "https://auth.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let deleted = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(deleted.starts_with("__Secure-session=;"));
    assert!(deleted.contains("; Max-Age=0; Secure"));
    assert_eq!(cookie_scope(&created), cookie_scope(deleted));

    assert_eq!(
        app.oneshot(sign_in("/api/auth/sign-in/username"))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn passkey_challenge_uses_the_configured_secure_cookie_scope() {
    let app = application(|config| {
        config.set_base_url("https://auth.example.com").unwrap();
        config.cookies.prefix = "lucid".into();
        config.cookies.default_attributes.path = Some("/api/auth".into());
        config
            .add_plugin(PasskeyPlugin::new(PasskeyConfig {
                rp_id: Some("example.com".into()),
                rp_name: Some("Example".into()),
                origins: Some(vec!["https://auth.example.com".into()]),
                webauthn_challenge_cookie: "passkey-challenge".into(),
                ..PasskeyConfig::default()
            }))
            .unwrap();
    })
    .await;
    let response = app
        .clone()
        .oneshot(sign_in("/api/auth/sign-in/username"))
        .await
        .unwrap();
    let session_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let response = app
        .oneshot(
            Request::get("/api/auth/passkey/generate-register-options")
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.starts_with("__Secure-lucid.passkey-challenge="));
    assert!(cookie.contains("; Path=/api/auth; Max-Age=300; Secure"));
}

#[tokio::test]
async fn cors_preflight_and_actual_response_use_only_trusted_origins() {
    let app = application(|config| {
        config.set_base_url("https://auth.example.com").unwrap();
        config.trust_origin("https://app.example.com").unwrap();
        config.enable_cors();
    })
    .await;
    let response = app
        .clone()
        .oneshot(
            Request::options("/api/auth/sign-in/username")
                .header(header::ORIGIN, "https://app.example.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://app.example.com"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
        "true"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "content-type"
    );

    let response = app
        .clone()
        .oneshot(
            Request::options("/api/auth/sign-in/username")
                .header(header::ORIGIN, "https://evil.test")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::ORIGIN, "https://app.example.com")
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "cors")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": "luna", "password": "password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://app.example.com"
    );
}
