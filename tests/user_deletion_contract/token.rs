use super::*;
use lucid_auth::{
    DeleteAccountVerification, DeleteAccountVerificationSender, VerificationIdentifierHasher,
    VerificationIdentifierStorage, VerificationStore,
};

#[derive(Clone, Default)]
struct CapturingSender {
    sent: Arc<Mutex<Vec<DeleteAccountVerification>>>,
}

#[async_trait]
impl DeleteAccountVerificationSender for CapturingSender {
    async fn send(&self, verification: DeleteAccountVerification) -> Result<(), AuthError> {
        self.sent.lock().await.push(verification);
        Ok(())
    }
}

async fn request_token(fixture: &Fixture, sender: &CapturingSender, cookie: &str) -> String {
    let response = fixture
        .app
        .clone()
        .oneshot(delete_request(cookie, json!({ "callbackURL": "/goodbye" })))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["message"],
        "Verification email sent"
    );
    sender.sent.lock().await.last().unwrap().token.clone()
}

async fn assert_token_shape_and_storage(
    fixture: &Fixture,
    sender: &CapturingSender,
    user: &lucid_auth::AuthUser,
    token: &str,
) {
    let sent = sender.sent.lock().await;
    let message = sent.last().unwrap();
    assert_eq!(message.user.id, user.id);
    assert!(message.url.contains("callbackURL=%2Fgoodbye"));
    assert_eq!(token.len(), 32);
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    );
    drop(sent);
    assert!(
        fixture
            .store
            .find_verification(&format!("delete-account-{token}"))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .store
            .find_verification(&format!("delete-account:{token}"))
            .await
            .unwrap()
            .is_none()
    );
}

async fn assert_wrong_user_burns_token(fixture: &Fixture, cookie: &str, token: &str) {
    let (wrong_cookie, _) = account(fixture, "wrong-delete-user@example.com").await;
    let wrong_user = fixture
        .app
        .clone()
        .oneshot(delete_request(&wrong_cookie, json!({ "token": token })))
        .await
        .unwrap();
    assert_eq!(wrong_user.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(wrong_user).await["code"], "INVALID_TOKEN");
    let burned = fixture
        .app
        .clone()
        .oneshot(delete_request(cookie, json!({ "token": token })))
        .await
        .unwrap();
    assert_eq!(burned.status(), StatusCode::NOT_FOUND);
}

async fn redeem_callback(fixture: &Fixture, cookie: &str, token: &str) {
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/delete-user/callback?token={token}&callbackURL=%2Fgoodbye"
            ))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[header::LOCATION], "/goodbye");
}

#[tokio::test]
async fn verification_tokens_are_purpose_bound_single_use_and_redirect_safely() {
    let sender = CapturingSender::default();
    let fixture = fixture(
        DeleteUserConfig {
            enabled: true,
            send_delete_account_verification: Some(Arc::new(sender.clone())),
            ..DeleteUserConfig::default()
        },
        None,
    )
    .await;
    let (cookie, user) = account(&fixture, "token-delete@example.com").await;
    let token = request_token(&fixture, &sender, &cookie).await;
    assert_token_shape_and_storage(&fixture, &sender, &user, &token).await;

    let invalid = fixture
        .app
        .clone()
        .oneshot(delete_request(&cookie, json!({ "token": "invalid" })))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(invalid).await["code"], "INVALID_TOKEN");
    assert_wrong_user_burns_token(&fixture, &cookie, &token).await;

    let replacement = request_token(&fixture, &sender, &cookie).await;
    redeem_callback(&fixture, &cookie, &replacement).await;
    assert!(
        fixture
            .store
            .find_user_by_id(user.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[derive(Debug)]
struct RecordingIdentifierHasher {
    inputs: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl VerificationIdentifierHasher for RecordingIdentifierHasher {
    async fn hash(&self, identifier: &str) -> Result<String, AuthError> {
        self.inputs.lock().await.push(identifier.to_owned());
        Ok(format!("stored:{identifier}"))
    }
}

#[tokio::test]
async fn deletion_identifier_is_transformed_once_after_the_complete_prefix() {
    let sender = CapturingSender::default();
    let inputs = Arc::new(Mutex::new(Vec::new()));
    let fixture = fixture_with_config(
        DeleteUserConfig {
            enabled: true,
            send_delete_account_verification: Some(Arc::new(sender.clone())),
            ..DeleteUserConfig::default()
        },
        None,
        |config| {
            config.verification.store_identifier.default =
                VerificationIdentifierStorage::Custom(Arc::new(RecordingIdentifierHasher {
                    inputs: inputs.clone(),
                }));
        },
    )
    .await;
    let (cookie, user) = account(&fixture, "custom-delete@example.com").await;
    let response = fixture
        .app
        .clone()
        .oneshot(delete_request(&cookie, json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let token = sender.sent.lock().await.last().unwrap().token.clone();
    let complete = format!("delete-account-{token}");
    assert_eq!(inputs.lock().await.as_slice(), [complete.as_str()]);
    assert!(
        fixture
            .store
            .find_verification(&format!("stored:{complete}"))
            .await
            .unwrap()
            .is_some()
    );

    let deleted = fixture
        .app
        .clone()
        .oneshot(delete_request(&cookie, json!({ "token": token })))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    assert!(
        fixture
            .store
            .find_user_by_id(user.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        inputs.lock().await.as_slice(),
        [complete.as_str(), complete.as_str()]
    );
}
