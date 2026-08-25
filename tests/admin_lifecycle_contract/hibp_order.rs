use super::*;
use async_trait::async_trait;
use lucid_auth::{
    HaveIBeenPwnedOptions, HaveIBeenPwnedPlugin, PasswordBreachCheckError, PasswordBreachChecker,
};

struct RejectCompromised;

#[async_trait]
impl PasswordBreachChecker for RejectCompromised {
    async fn is_compromised(&self, password: &str) -> Result<bool, PasswordBreachCheckError> {
        Ok(password == "compromised password")
    }
}

#[tokio::test]
async fn failure_leaves_created_user_without_changing_existing_credentials() {
    let mut config = AuthConfig::new([143_u8; 32]).unwrap();
    config
        .add_plugin(HaveIBeenPwnedPlugin::with_checker(
            HaveIBeenPwnedOptions::default(),
            Arc::new(RejectCompromised),
        ))
        .unwrap();
    let app = application_with_config(config, AdminConfig::default()).await;
    let (status, owner_cookie) = sign_in(&app, "luna", "password").await;
    assert_eq!(status, StatusCode::OK);

    let (status, error) = request_json(
        &app,
        Request::post("/api/auth/admin/create-user")
            .header(header::COOKIE, &owner_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email": "persisted@example.com",
                    "password": "compromised password",
                    "name": "Persisted",
                    "data": { "username": "persisted" }
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "PASSWORD_COMPROMISED");
    assert_created_user_has_no_credential(&app, &owner_cookie).await;

    let created = create_user(&app, &owner_cookie, "unchanged", "user").await;
    let user_id = created["user"]["id"].as_str().unwrap();
    let (status, error) = request_json(
        &app,
        Request::post("/api/auth/admin/set-user-password")
            .header(header::COOKIE, &owner_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "userId": user_id, "newPassword": "compromised password" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "PASSWORD_COMPROMISED");
    assert_eq!(
        sign_in(&app, "unchanged", "initial-password").await.0,
        StatusCode::OK
    );
}

async fn assert_created_user_has_no_credential(app: &Router, owner_cookie: &str) {
    let (status, users) = request_json(
        app,
        Request::get("/api/auth/admin/list-users")
            .header(header::COOKIE, owner_cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(users["users"].as_array().unwrap().iter().any(|user| {
        user["email"] == "persisted@example.com" && user["username"] == "persisted"
    }));
    assert_eq!(
        sign_in(app, "persisted", "compromised password").await.0,
        StatusCode::UNAUTHORIZED
    );
}
