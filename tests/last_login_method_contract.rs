use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthStore, LastLoginMethodConfig, LastLoginMethodPlugin,
    MemoryStore, NewPasswordUser,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

struct Fixture {
    app: Router,
    service: Arc<AuthService>,
    store: Arc<MemoryStore>,
}

fn fixture(configure: impl FnOnce(&mut AuthConfig, &mut LastLoginMethodConfig)) -> Fixture {
    let mut auth = AuthConfig::new([129_u8; 32]).unwrap();
    auth.set_base_url("http://localhost").unwrap();
    auth.email_and_password.enabled = true;
    let mut last_login = LastLoginMethodConfig::default();
    configure(&mut auth, &mut last_login);
    auth.add_plugin(LastLoginMethodPlugin::new(last_login))
        .unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), auth));
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        service,
        store,
    }
}

async fn post(app: &Router, path: &str, body: Value) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::post(path)
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn last_login_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|cookie| cookie.starts_with(&format!("{name}=")))
        .map(str::to_owned)
}

fn signup(email: &str) -> Value {
    json!({
        "email": email,
        "password": "correct horse battery staple",
        "name": "Contract User"
    })
}

#[tokio::test]
async fn plugin_is_optional_and_declares_no_routes_or_migrations() {
    let fixture = fixture(|_, _| {});
    let descriptor = fixture
        .service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "last-login-method")
        .unwrap();
    assert!(descriptor.endpoints.is_empty());
    assert_eq!(
        descriptor.cookies[0].name,
        "better-auth.last_used_login_method"
    );
    assert_eq!(descriptor.client.unwrap().factory, "lastLoginMethodClient");
    assert!(fixture.service.plugin_migrations().is_empty());
    assert!(
        fixture
            .service
            .database_schema_fields(lucid_auth::DatabaseModel::User)
            .get("lastLoginMethod")
            .is_none()
    );
}

#[tokio::test]
async fn email_signup_emits_the_exact_readable_cookie_and_signout_preserves_it() {
    let fixture = fixture(|_, _| {});
    let response = post(
        &fixture.app,
        "/api/auth/sign-up/email",
        signup("cookie@example.com"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        last_login_cookie(response.headers(), "better-auth.last_used_login_method").as_deref(),
        Some("better-auth.last_used_login_method=email; Max-Age=2592000; Path=/; SameSite=Lax")
    );
    let session = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|cookie| cookie.starts_with("better-auth.session_token="))
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let signout = fixture
        .app
        .oneshot(
            Request::post("/api/auth/sign-out")
                .header(header::ORIGIN, "http://localhost")
                .header(header::COOKIE, session)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signout.status(), StatusCode::OK);
    assert!(last_login_cookie(signout.headers(), "better-auth.last_used_login_method").is_none());
}

#[tokio::test]
async fn custom_resolution_encoding_attributes_and_consent_match_upstream() {
    let allowed = fixture(|auth, config| {
        auth.cookies.default_attributes.domain = Some(".example.com".into());
        auth.cookies.default_attributes.path = Some("/auth".into());
        config.cookie_name = "custom.last-login".into();
        config.max_age = 12.9;
        config.custom_resolve_method =
            Some(Arc::new(|_context: &_| Ok(Some("oidc/google +foo".into()))));
    });
    let response = post(
        &allowed.app,
        "/api/auth/sign-up/email",
        signup("encoded@example.com"),
    )
    .await;
    assert_eq!(
        last_login_cookie(response.headers(), "custom.last-login").as_deref(),
        Some(
            "custom.last-login=oidc%2Fgoogle%20%2Bfoo; Max-Age=12; Domain=.example.com; Path=/auth; SameSite=Lax"
        )
    );

    let denied = fixture(|_, config| {
        config.before_store_cookie = Some(Arc::new(|_, _| async { Ok(false) }));
    });
    let response = post(
        &denied.app,
        "/api/auth/sign-up/email",
        signup("denied@example.com"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(last_login_cookie(response.headers(), "better-auth.last_used_login_method").is_none());

    let failed = fixture(|_, config| {
        config.before_store_cookie = Some(Arc::new(|_, _| async {
            Err(AuthError::Storage("consent failed".into()))
        }));
    });
    let response = post(
        &failed.app,
        "/api/auth/sign-up/email",
        signup("failed-consent@example.com"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(last_login_cookie(response.headers(), "better-auth.last_used_login_method").is_none());
}

#[tokio::test]
async fn unsupported_default_paths_do_not_write_a_cookie() {
    let fixture = fixture(|_, _| {});
    let response = fixture
        .app
        .oneshot(
            Request::get("/api/auth/get-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(last_login_cookie(response.headers(), "better-auth.last_used_login_method").is_none());
}

#[tokio::test]
async fn database_storage_uses_schema_hooks_and_skips_native_calls_without_context() {
    let fixture = fixture(|_, config| {
        config.store_in_database = true;
        config.schema.user.last_login_method_field_name = Some("last_login_method".into());
        config.custom_resolve_method =
            Some(Arc::new(|context: &lucid_auth::LastLoginMethodContext| {
                Ok(match context.path.as_str() {
                    "/sign-up/email" => Some("created-with-email".into()),
                    "/sign-in/email" => Some("signed-in-with-email".into()),
                    _ => None,
                })
            }));
    });
    let field = fixture
        .service
        .database_schema_fields(lucid_auth::DatabaseModel::User)
        .get("lastLoginMethod")
        .unwrap();
    assert!(!field.required);
    assert!(!field.input);
    assert_eq!(field.field_name.as_deref(), Some("last_login_method"));

    let response = post(
        &fixture.app,
        "/api/auth/sign-up/email",
        signup("stored@example.com"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let user = fixture
        .store
        .find_user_by_email("stored@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        user.additional_fields["lastLoginMethod"],
        "created-with-email"
    );

    let response = post(
        &fixture.app,
        "/api/auth/sign-in/email",
        json!({
            "email": "stored@example.com",
            "password": "correct horse battery staple"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let user = fixture
        .store
        .find_user_by_email("stored@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        user.additional_fields["lastLoginMethod"],
        "signed-in-with-email"
    );

    let native = fixture
        .service
        .provision_password_user(NewPasswordUser {
            username: "native_user".into(),
            name: "Native User".into(),
            email: Some("native@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
    assert!(!native.additional_fields.contains_key("lastLoginMethod"));
}
