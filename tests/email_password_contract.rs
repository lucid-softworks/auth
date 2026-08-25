use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AccessStore, AuthConfig, AuthError, AuthService, EmailSignUpInput, HaveIBeenPwnedOptions,
    HaveIBeenPwnedPlugin, MemoryStore, PasswordBreachCheckError, PasswordBreachChecker,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

struct RejectCompromised;

#[async_trait]
impl PasswordBreachChecker for RejectCompromised {
    async fn is_compromised(&self, password: &str) -> Result<bool, PasswordBreachCheckError> {
        Ok(password == "compromised password")
    }
}

fn application(
    configure: impl FnOnce(&mut AuthConfig),
) -> (Router, Arc<AuthService>, Arc<MemoryStore>) {
    let mut config = AuthConfig::new([97_u8; 32]).unwrap();
    config.trust_origin("http://localhost").unwrap();
    configure(&mut config);
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    let app = lucid_auth::axum::router(service.clone());
    (app, service, store)
}

async fn post(app: &Router, path: &str, body: Value) -> (StatusCode, axum::http::HeaderMap, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (status, headers, body)
}

#[tokio::test]
async fn email_signup_and_signin_match_the_core_wire_contract() {
    let (app, _, _) = application(|config| config.email_and_password.enabled = true);
    let (status, headers, signup) = post(
        &app,
        "/api/auth/sign-up/email",
        json!({
            "name": "Casey",
            "email": "Casey.Test@Example.com",
            "password": "correct horse battery staple",
            "image": "https://example.com/casey.png",
            "callbackURL": "/verify",
            "rememberMe": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(signup["token"].is_string());
    assert_eq!(signup["user"]["email"], "casey.test@example.com");
    assert_eq!(signup["user"]["image"], "https://example.com/casey.png");
    assert!(headers.contains_key(header::SET_COOKIE));
    let cookie = headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let verified = app
        .clone()
        .oneshot(
            Request::post("/api/auth/verify-password")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .header(header::COOKIE, cookie)
                .body(Body::from(
                    json!({ "password": "correct horse battery staple" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verified.status(), StatusCode::OK);

    let (status, _, duplicate) = post(
        &app,
        "/api/auth/sign-up/email",
        json!({
            "name": "Duplicate",
            "email": "CASEY.TEST@example.com",
            "password": "correct horse battery staple"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(duplicate["code"], "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
}

#[tokio::test]
async fn email_signin_honors_remember_me_and_exact_callback_casing() {
    let (app, service, _) = application(|config| config.email_and_password.enabled = true);
    let _ = post(
        &app,
        "/api/auth/sign-up/email",
        json!({
            "name": "Casey",
            "email": "casey.test@example.com",
            "password": "correct horse battery staple"
        }),
    )
    .await;

    let (status, headers, signin) = post(
        &app,
        "/api/auth/sign-in/email",
        json!({
            "email": "CASEY.TEST@example.com",
            "password": "correct horse battery staple",
            "callbackURL": "/dashboard",
            "rememberMe": false
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(signin["redirect"], true);
    assert_eq!(signin["url"], "/dashboard");
    assert_eq!(headers[header::LOCATION], "/dashboard");
    assert!(
        !headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age")
    );
    let stored = service
        .session(signin["token"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    let remaining = stored.session.expires_at - stored.session.created_at;
    assert!(remaining.num_hours() <= 24 && remaining.num_hours() >= 23);

    let (status, _, alias) = post(
        &app,
        "/api/auth/sign-in/email",
        json!({
            "email": "casey.test@example.com",
            "password": "correct horse battery staple",
            "callbackUrl": "/wrong-casing"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(alias["redirect"], false);
    assert!(alias["url"].is_null());
}

#[tokio::test]
async fn credential_routes_accept_urlencoded_forms_and_hide_failures() {
    let (app, _, _) = application(|config| config.email_and_password.enabled = true);
    let form_response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(
                    "name=Form+User&email=Form.User%40Example.com&password=correct+horse+battery+staple&callbackURL=%2Fverify",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(form_response.status(), StatusCode::OK);
    let form: Value = serde_json::from_slice(
        &form_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(form["user"]["email"], "form.user@example.com");

    let (status, _, invalid) = post(
        &app,
        "/api/auth/sign-in/email",
        json!({
            "email": "casey.test@example.com",
            "password": "wrong password"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(invalid["code"], "INVALID_EMAIL_OR_PASSWORD");
}

#[tokio::test]
async fn disabled_modes_and_password_bounds_match_better_auth() {
    let (disabled, _, _) = application(|_| {});
    let (status, _, error) = post(
        &disabled,
        "/api/auth/sign-in/email",
        json!({ "email": "casey@example.com", "password": "password" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "EMAIL_PASSWORD_DISABLED");

    let (disabled_signup, _, _) = application(|config| {
        config.email_and_password.enabled = true;
        config.email_and_password.disable_sign_up = true;
    });
    let (status, _, error) = post(
        &disabled_signup,
        "/api/auth/sign-up/email",
        json!({ "name": "Casey", "email": "casey@example.com", "password": "password" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "EMAIL_PASSWORD_SIGN_UP_DISABLED");

    let (bounded, _, _) = application(|config| {
        config.email_and_password.enabled = true;
        config.email_and_password.min_password_length = 12;
        config.email_and_password.max_password_length = 16;
    });
    let (status, _, error) = post(
        &bounded,
        "/api/auth/sign-up/email",
        json!({ "name": "Short", "email": "short@example.com", "password": "password" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "PASSWORD_TOO_SHORT");
    let (status, _, error) = post(
        &bounded,
        "/api/auth/sign-up/email",
        json!({
            "name": "Long",
            "email": "long@example.com",
            "password": "password-is-far-too-long"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "PASSWORD_TOO_LONG");
}

#[tokio::test]
async fn disabled_auto_signin_uses_generic_duplicate_responses() {
    let (no_auto_signin, _, _) = application(|config| {
        config.email_and_password.enabled = true;
        config.email_and_password.auto_sign_in = false;
    });
    let no_auto_body = json!({
        "name": "No Session",
        "email": "no-session@example.com",
        "password": "correct horse battery staple"
    });
    let (status, headers, created) = post(
        &no_auto_signin,
        "/api/auth/sign-up/email",
        no_auto_body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(created["token"].is_null());
    assert!(!headers.contains_key(header::SET_COOKIE));
    let (status, _, duplicate) =
        post(&no_auto_signin, "/api/auth/sign-up/email", no_auto_body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(duplicate["token"].is_null());
}

#[tokio::test]
async fn hibp_prevents_new_signup_and_preempts_the_generic_duplicate_response() {
    let (app, _, store) = application(|config| {
        config.email_and_password.enabled = true;
        config.email_and_password.auto_sign_in = false;
        config
            .add_plugin(HaveIBeenPwnedPlugin::with_checker(
                HaveIBeenPwnedOptions::default(),
                Arc::new(RejectCompromised),
            ))
            .unwrap();
    });
    let compromised = json!({
        "name": "Rejected",
        "email": "rejected@example.com",
        "password": "compromised password"
    });
    let (status, _, error) = post(&app, "/api/auth/sign-up/email", compromised.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "PASSWORD_COMPROMISED");
    assert_eq!(store.count_users(&[]).await.unwrap(), 0);

    let (status, _, created) = post(
        &app,
        "/api/auth/sign-up/email",
        json!({
            "name": "Existing",
            "email": "rejected@example.com",
            "password": "safe original password"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(store.count_users(&[]).await.unwrap(), 1);

    let (status, _, error) = post(&app, "/api/auth/sign-up/email", compromised).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "PASSWORD_COMPROMISED");
    assert_eq!(store.count_users(&[]).await.unwrap(), 1);
}

#[tokio::test]
async fn verification_required_mode_hides_duplicates_and_rejects_signin() {
    let (verification, _, store) = application(|config| {
        config.email_and_password.enabled = true;
        config.email_and_password.require_email_verification = true;
    });
    let signup = json!({
        "name": "Casey",
        "email": "casey@example.com",
        "password": "correct horse battery staple"
    });
    let (status, headers, created) =
        post(&verification, "/api/auth/sign-up/email", signup.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(created["token"].is_null());
    assert!(!headers.contains_key(header::SET_COOKIE));
    let real_id = created["user"]["id"].clone();

    let (status, _, synthetic) = post(
        &verification,
        "/api/auth/sign-up/email",
        json!({
            "name": "Casey",
            "email": "CASEY@example.com",
            "password": "correct horse battery staple"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(synthetic["token"].is_null());
    assert_ne!(synthetic["user"]["id"], real_id);
    assert_eq!(store.count_users(&[]).await.unwrap(), 1);

    let (status, _, error) = post(
        &verification,
        "/api/auth/sign-in/email",
        json!({
            "email": "casey@example.com",
            "password": "correct horse battery staple"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error["code"], "EMAIL_NOT_VERIFIED");
}

#[tokio::test]
async fn concurrent_case_variant_signup_creates_one_account() {
    let (_, service, store) = application(|config| config.email_and_password.enabled = true);
    let signup = |email: &str| EmailSignUpInput {
        name: "Casey".into(),
        email: email.into(),
        password: "correct horse battery staple".into(),
        image: None,
        callback_url: None,
        remember_me: None,
        username: None,
        display_username: None,
        additional_fields: serde_json::Map::new(),
    };
    let (first, second) = tokio::join!(
        service.sign_up_email(signup("Casey@Example.com"), None, None),
        service.sign_up_email(signup("casey@example.com"), None, None),
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let error = first.err().or_else(|| second.err()).unwrap();
    assert!(matches!(error, AuthError::UserAlreadyExistsEmail));
    assert_eq!(store.count_users(&[]).await.unwrap(), 1);
}
