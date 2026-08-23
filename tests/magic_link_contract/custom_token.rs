use super::*;

struct FixedToken;

#[async_trait]
impl MagicLinkTokenGenerator for FixedToken {
    async fn generate(&self, _email: &str) -> Result<String, AuthError> {
        Ok("FixedMagicLinkToken".into())
    }
}

struct PrefixHasher;

#[async_trait]
impl MagicLinkTokenHasher for PrefixHasher {
    async fn hash(&self, token: &str) -> Result<String, AuthError> {
        Ok(format!("stored:{token}"))
    }
}

#[tokio::test]
async fn custom_token_storage_and_concurrent_redemption_consume_once() {
    let (app, _, sender) = application(|_, magic| {
        magic.token_generator = Some(Arc::new(FixedToken));
        magic.token_storage = MagicLinkTokenStorage::Custom(Arc::new(PrefixHasher));
        magic.allowed_attempts = 9;
    });
    request_link(
        &app,
        json!({ "email": "concurrent@example.com", "name": "Concurrent" }),
    )
    .await;
    assert_eq!(
        sender.messages.lock().await[0].0.token,
        "FixedMagicLinkToken"
    );
    let request = || {
        Request::get("/api/auth/magic-link/verify?token=FixedMagicLinkToken")
            .body(Body::empty())
            .unwrap()
    };
    let (left, right) = tokio::join!(
        app.clone().oneshot(request()),
        app.clone().oneshot(request())
    );
    let statuses = [left.unwrap().status(), right.unwrap().status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::FOUND)
            .count(),
        1
    );
}
