use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, MemoryStore, MultiSessionConfig, MultiSessionPlugin, NewPasswordUser,
    UsernamePlugin,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

struct Fixture {
    app: Router,
    service: Arc<AuthService>,
}

#[derive(Default, Clone)]
struct CookieJar(BTreeMap<String, String>);

impl CookieJar {
    fn request_header(&self) -> String {
        self.0
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn apply(&mut self, headers: &HeaderMap) {
        for value in headers.get_all(header::SET_COOKIE) {
            let value = value.to_str().unwrap();
            let pair = value.split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            if value.is_empty() || value.contains("Max-Age=0") {
                self.0.remove(name);
            } else {
                self.0.insert(name.to_owned(), value.to_owned());
            }
        }
    }

    fn main_token(&self, service: &AuthService) -> Option<String> {
        self.0
            .get("better-auth.session_token")
            .and_then(|value| service.verify_cookie_value(value))
    }

    fn selectors(&self) -> Vec<(String, String)> {
        self.0
            .iter()
            .filter(|(name, _)| name.contains("_multi-"))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }
}

async fn fixture(maximum_sessions: f64) -> Fixture {
    let mut config = AuthConfig::new([b'R'; 32]).unwrap();
    config.trust_origin("http://localhost").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    config
        .add_plugin(MultiSessionPlugin::new(MultiSessionConfig {
            maximum_sessions,
        }))
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    for (username, name) in [("luna", "Luna"), ("casey", "Casey")] {
        service
            .provision_password_user(NewPasswordUser {
                username: username.into(),
                name: name.into(),
                email: None,
                password: "password".into(),
                role: "user".into(),
            })
            .await
            .unwrap();
    }
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        service,
    }
}

async fn send(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.unwrap()
}

fn post(path: &str, jar: Option<&CookieJar>, body: Value) -> Request<Body> {
    let mut request = Request::post(path)
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(jar) = jar {
        request = request.header(header::COOKIE, jar.request_header());
    }
    request.body(Body::from(body.to_string())).unwrap()
}

async fn sign_in(fixture: &Fixture, jar: &mut CookieJar, username: &str) -> String {
    let response = send(
        &fixture.app,
        post(
            "/api/auth/sign-in/username",
            Some(jar),
            json!({ "username": username, "password": "password" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    jar.apply(response.headers());
    jar.main_token(&fixture.service).unwrap()
}

async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn plugin_is_optional_and_describes_only_the_official_surface() {
    let config = AuthConfig::new([31_u8; 32]).unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let response = send(
        &lucid_auth::axum::router(service),
        Request::get("/api/auth/multi-session/list-device-sessions")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let fixture = fixture(5.0).await;
    let descriptor = fixture
        .service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "multi-session")
        .unwrap();
    assert_eq!(descriptor.endpoints.len(), 3);
    assert_eq!(descriptor.client.unwrap().factory, "multiSessionClient");
    assert!(descriptor.cookies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
    assert!(fixture.service.plugin_migrations().is_empty());
}

#[tokio::test]
async fn selectors_list_and_activate_sessions_exactly() {
    let fixture = fixture(5.0).await;
    let mut jar = CookieJar::default();
    let luna = sign_in(&fixture, &mut jar, "luna").await;
    assert_eq!(jar.selectors().len(), 1);
    let casey = sign_in(&fixture, &mut jar, "casey").await;
    assert_eq!(jar.selectors().len(), 2);

    let response = send(
        &fixture.app,
        Request::get("/api/auth/multi-session/list-device-sessions")
            .header(header::COOKIE, jar.request_header())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let listed = json_body(response).await;
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["session"]["token"] == luna)
    );
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["session"]["token"] == casey)
    );

    jar.0.remove("better-auth.session_token");
    let response = send(
        &fixture.app,
        post(
            "/api/auth/multi-session/set-active",
            Some(&jar),
            json!({ "sessionToken": luna, "unknown": "stripped" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    jar.apply(response.headers());
    assert_eq!(
        jar.main_token(&fixture.service).as_deref(),
        Some(luna.as_str())
    );
    assert!(fixture.service.session(&casey).await.unwrap().is_some());
}

#[tokio::test]
async fn same_user_replacement_and_quota_match_upstream_boundaries() {
    let fixture = fixture(1.0).await;
    let mut jar = CookieJar::default();
    let first = sign_in(&fixture, &mut jar, "luna").await;
    let second = sign_in(&fixture, &mut jar, "luna").await;
    assert_ne!(first, second);
    assert!(fixture.service.session(&first).await.unwrap().is_none());
    assert_eq!(jar.selectors().len(), 1);

    let casey = sign_in(&fixture, &mut jar, "casey").await;
    assert_eq!(
        jar.main_token(&fixture.service).as_deref(),
        Some(casey.as_str())
    );
    assert_eq!(
        jar.selectors().len(),
        1,
        "quota suppresses the new selector"
    );
}

#[tokio::test]
async fn activation_errors_and_duplicate_cookie_lookup_match_better_call() {
    let fixture = fixture(5.0).await;
    let mut jar = CookieJar::default();
    let token = sign_in(&fixture, &mut jar, "luna").await;
    let (selector_name, valid_value) = jar.selectors().pop().unwrap();
    let duplicate_header = format!(
        "{selector_name}={valid_value}; {selector_name}=invalid; unrelated_multi-x=invalid"
    );
    let response = send(
        &fixture.app,
        Request::get("/api/auth/multi-session/list-device-sessions")
            .header(header::COOKIE, duplicate_header)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(json_body(response).await.as_array().unwrap().len(), 1);

    let mut alias = CookieJar::default();
    alias.0.insert(
        "better-auth.session_token_multi-alias".into(),
        fixture.service.signed_cookie_value(&token),
    );
    let response = send(
        &fixture.app,
        post(
            "/api/auth/multi-session/set-active",
            Some(&alias),
            json!({ "sessionToken": "alias" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    alias.apply(response.headers());
    assert_eq!(
        alias.main_token(&fixture.service).as_deref(),
        Some(token.as_str())
    );

    let response = send(
        &fixture.app,
        post(
            "/api/auth/multi-session/set-active",
            None,
            json!({ "sessionToken": token }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(response).await,
        json!({ "code": "INVALID_SESSION_TOKEN", "message": "Invalid session token" })
    );
}

#[tokio::test]
async fn revoking_current_session_replaces_then_clears_it() {
    let fixture = fixture(5.0).await;
    let mut jar = CookieJar::default();
    let luna = sign_in(&fixture, &mut jar, "luna").await;
    let casey = sign_in(&fixture, &mut jar, "casey").await;

    let response = send(
        &fixture.app,
        post(
            "/api/auth/multi-session/revoke",
            Some(&jar),
            json!({ "sessionToken": casey }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    jar.apply(response.headers());
    assert_eq!(
        jar.main_token(&fixture.service).as_deref(),
        Some(luna.as_str())
    );
    assert!(fixture.service.session(&casey).await.unwrap().is_none());

    let response = send(
        &fixture.app,
        post(
            "/api/auth/multi-session/revoke",
            Some(&jar),
            json!({ "sessionToken": luna }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    jar.apply(response.headers());
    assert!(jar.main_token(&fixture.service).is_none());
    assert!(jar.selectors().is_empty());
}

#[tokio::test]
async fn sign_out_removes_only_verified_multi_session_cookies() {
    let fixture = fixture(5.0).await;
    let mut jar = CookieJar::default();
    let luna = sign_in(&fixture, &mut jar, "luna").await;
    let casey = sign_in(&fixture, &mut jar, "casey").await;
    jar.0.insert("unrelated_multi-x".into(), "invalid".into());

    let response = send(
        &fixture.app,
        post("/api/auth/sign-out", Some(&jar), json!({})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    jar.apply(response.headers());
    assert!(fixture.service.session(&luna).await.unwrap().is_none());
    assert!(fixture.service.session(&casey).await.unwrap().is_none());
    assert_eq!(jar.selectors().len(), 1);
    assert_eq!(
        jar.0.get("unrelated_multi-x").map(String::as_str),
        Some("invalid")
    );
}
