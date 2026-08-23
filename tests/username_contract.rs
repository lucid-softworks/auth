use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthStore, EmailSignUpInput, MemoryStore, UsernameConfig,
    UsernameError, UsernamePlugin, UsernameValidationOrder, UsernameValidationTiming,
    UsernameValidator,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn configured_service(config: UsernameConfig) -> (Arc<AuthService>, Arc<MemoryStore>) {
    let mut auth = AuthConfig::new([126_u8; 32]).unwrap();
    auth.email_and_password.enabled = true;
    auth.set_base_url("http://localhost").unwrap();
    auth.add_plugin(UsernamePlugin::new(config)).unwrap();
    let store = Arc::new(MemoryStore::default());
    (Arc::new(AuthService::new(store.clone(), auth)), store)
}

async fn sign_up_username(app: &Router) -> (String, Value) {
    let signup = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(
                    json!({
                        "name": "Mixed User",
                        "email": "mixed@example.com",
                        "password": "correct horse battery staple",
                        "username": "Mixed_User",
                        "displayUsername": "Mixed User"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signup.status(), StatusCode::OK);
    let cookie = signup
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    (cookie, response_json(signup).await)
}

#[tokio::test]
async fn username_routes_and_signup_fields_exist_only_with_the_plugin() {
    let mut config = AuthConfig::new([125_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let app: Router = lucid_auth::axum::router(service.clone());
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/is-username-available")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"username":"casey"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let signup = app
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "Casey",
                        "email": "casey@example.com",
                        "password": "correct horse battery staple",
                        "username": "casey",
                        "displayUsername": "Casey"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signup.status(), StatusCode::OK);
    let signup = response_json(signup).await;
    assert!(signup["user"].get("username").is_none());
    assert!(signup["user"].get("displayUsername").is_none());
}

#[tokio::test]
async fn official_signup_availability_update_and_signin_lifecycle_matches() {
    let (service, store) = configured_service(UsernameConfig::default());
    let app: Router = lucid_auth::axum::router(service);
    let (cookie, signed_up) = sign_up_username(&app).await;
    assert_eq!(signed_up["user"]["username"], "mixed_user");
    assert_eq!(signed_up["user"]["displayUsername"], "Mixed User");

    let availability = app
        .clone()
        .oneshot(
            Request::post("/api/auth/is-username-available")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"username":"MIXED_USER"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(availability.status(), StatusCode::OK);
    assert_eq!(response_json(availability).await["available"], false);

    let updated = app
        .clone()
        .oneshot(
            Request::post("/api/auth/update-user")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .header(header::COOKIE, &cookie)
                .body(Body::from(
                    r#"{"username":"Renamed_User","displayUsername":"Renamed User"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(response_json(updated).await["status"], true);
    let stored = store
        .find_user_by_username("renamed_user")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.display_username.as_deref(), Some("Renamed User"));

    let signed_in = app
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"username":"RENAMED_USER","password":"correct horse battery staple"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signed_in.status(), StatusCode::OK);
    assert_eq!(
        response_json(signed_in).await["user"]["username"],
        "renamed_user"
    );
}

#[tokio::test]
async fn concurrent_normalized_duplicates_create_exactly_one_user() {
    let (service, _) = configured_service(UsernameConfig::default());
    let signup = |email: &str, username: &str| EmailSignUpInput {
        name: "Concurrent User".into(),
        email: email.into(),
        password: "correct horse battery staple".into(),
        image: None,
        callback_url: None,
        remember_me: None,
        username: Some(username.into()),
        display_username: None,
    };
    let (left, right) = tokio::join!(
        service.sign_up_email(signup("left@example.com", "Concurrent_User"), None, None),
        service.sign_up_email(signup("right@example.com", "concurrent_user"), None, None),
    );
    let results = [left, right];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(AuthError::Username(UsernameError::AlreadyTaken))
            ))
            .count(),
        1
    );
}

#[tokio::test]
async fn validation_errors_use_the_official_route_specific_statuses() {
    let (service, _) = configured_service(UsernameConfig::default());
    let app: Router = lucid_auth::axum::router(service);
    let available = app
        .clone()
        .oneshot(
            Request::post("/api/auth/is-username-available")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"username":"ab"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(available.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response_json(available).await["code"], "USERNAME_TOO_SHORT");

    let signup = app
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(
                    json!({
                        "name": "Short",
                        "email": "short@example.com",
                        "password": "correct horse battery staple",
                        "username": "ab"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signup.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(signup).await["code"], "USERNAME_TOO_SHORT");
}

#[tokio::test]
async fn disabled_display_username_is_neither_stored_nor_returned() {
    let (service, store) = configured_service(UsernameConfig {
        display_username: false,
        ..UsernameConfig::default()
    });
    let app: Router = lucid_auth::axum::router(service);
    let signup = app
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(
                    json!({
                        "name": "No Display",
                        "email": "no-display@example.com",
                        "password": "correct horse battery staple",
                        "username": "no_display",
                        "displayUsername": "No Display"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signup.status(), StatusCode::OK);
    let body = response_json(signup).await;
    assert_eq!(body["user"]["username"], "no_display");
    assert!(body["user"].get("displayUsername").is_none());
    let stored = store
        .find_user_by_username("no_display")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.display_username, None);
}

struct UnicodeSlugValidator;

#[async_trait]
impl UsernameValidator for UnicodeSlugValidator {
    async fn is_valid(&self, value: &str) -> bool {
        value
            .chars()
            .all(|character| character.is_alphanumeric() || character == '-')
    }
}

#[tokio::test]
async fn custom_normalization_validation_and_immutable_usernames_apply_in_order() {
    let config = UsernameConfig {
        max_username_length: 9,
        username_normalizer: Some(Arc::new(|value: &str| {
            value.to_lowercase().replace(' ', "-")
        })),
        username_validator: Some(Arc::new(UnicodeSlugValidator)),
        validation_order: UsernameValidationOrder {
            username: UsernameValidationTiming::PostNormalization,
            ..UsernameValidationOrder::default()
        },
        immutable_username: true,
        ..UsernameConfig::default()
    };
    let (service, _) = configured_service(config);
    let signup = service
        .sign_up_email(
            EmailSignUpInput {
                name: "Jöhn".into(),
                email: "unicode@example.com".into(),
                password: "correct horse battery staple".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                username: Some("JÖHN User".into()),
                display_username: None,
            },
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(signup.user.username.as_deref(), Some("jöhn-user"));
    assert_eq!(signup.user.display_username.as_deref(), Some("JÖHN User"));
    let session = service
        .session(signup.token.as_deref().unwrap())
        .await
        .unwrap()
        .unwrap();
    let error = service
        .update_current_user(
            &session,
            lucid_auth::UserProfileUpdate {
                username: Some("otheruser".into()),
                ..lucid_auth::UserProfileUpdate::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AuthError::Username(UsernameError::Immutable)
    ));
}
