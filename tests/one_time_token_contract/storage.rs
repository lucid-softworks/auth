use super::support::{fixture, fixture_with, generate, generated_token, signup};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Duration;
use lucid_auth::{
    AuthError, MemorySecondaryStorage, OneTimeTokenConfig, OneTimeTokenGenerator,
    OneTimeTokenHasher, OneTimeTokenRequestContext, OneTimeTokenStorage, SessionWithUser,
    VerificationIdentifierStorage,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

struct FixedGenerator {
    token: String,
    calls: Mutex<Vec<(uuid::Uuid, OneTimeTokenRequestContext)>>,
}

impl FixedGenerator {
    fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl OneTimeTokenGenerator for FixedGenerator {
    async fn generate(
        &self,
        session: &SessionWithUser,
        context: &OneTimeTokenRequestContext,
    ) -> Result<String, AuthError> {
        self.calls
            .lock()
            .await
            .push((session.session.id, context.clone()));
        Ok(self.token.clone())
    }
}

struct PrefixHasher;

#[async_trait]
impl OneTimeTokenHasher for PrefixHasher {
    async fn hash(&self, token: &str) -> Result<String, AuthError> {
        Ok(format!("stored:{token}"))
    }
}

struct EmptyHasher;

#[async_trait]
impl OneTimeTokenHasher for EmptyHasher {
    async fn hash(&self, _token: &str) -> Result<String, AuthError> {
        Ok(String::new())
    }
}

fn fixed_config(token: &str, storage: OneTimeTokenStorage) -> OneTimeTokenConfig {
    OneTimeTokenConfig {
        generator: Some(Arc::new(FixedGenerator::new(token))),
        token_storage: storage,
        ..OneTimeTokenConfig::default()
    }
}

#[tokio::test]
async fn defaults_use_better_auth_random_alphabet_plain_storage_and_three_minutes() {
    let fixture = fixture(OneTimeTokenConfig::default());
    let source = signup(&fixture, "defaults").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    assert_eq!(token.len(), 32);
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
    let record = fixture
        .service
        .find_verification_value(&format!("one-time-token:{token}"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.identifier, format!("one-time-token:{token}"));
    assert_eq!(record.value, source.token);
    assert_eq!(record.expires_at - record.created_at, Duration::minutes(3));
}

#[tokio::test]
async fn hashed_and_custom_storage_transform_only_the_persisted_identifier() {
    let public = "Fixed_Public-Token";
    let hashed = fixture(fixed_config(public, OneTimeTokenStorage::Hashed));
    let source = signup(&hashed, "hashed").await;
    let token = generated_token(generate(&hashed.app, Some(&source.cookie)).await).await;
    assert_eq!(token, public);
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(public.as_bytes()));
    let record = hashed
        .service
        .find_verification_value(&format!("one-time-token:{digest}"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.identifier, format!("one-time-token:{digest}"));
    assert_eq!(record.value, source.token);
    assert_eq!(
        hashed
            .service
            .verify_one_time_token(public)
            .await
            .unwrap()
            .user
            .id,
        source.user_id
    );

    let custom = fixture(fixed_config(
        public,
        OneTimeTokenStorage::Custom(Arc::new(PrefixHasher)),
    ));
    let source = signup(&custom, "custom-hash").await;
    let token = generated_token(generate(&custom.app, Some(&source.cookie)).await).await;
    assert_eq!(token, public);
    assert!(
        custom
            .service
            .find_verification_value(&format!("one-time-token:stored:{public}"))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        custom
            .service
            .verify_one_time_token(public)
            .await
            .unwrap()
            .user
            .id,
        source.user_id
    );
}

#[tokio::test]
async fn custom_generator_receives_the_session_and_exact_request_context() {
    let generator = Arc::new(FixedGenerator::new("context-token"));
    let fixture = fixture(OneTimeTokenConfig {
        generator: Some(generator.clone()),
        ..OneTimeTokenConfig::default()
    });
    let source = signup(&fixture, "context").await;
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::get("/api/auth/one-time-token/generate?source=contract")
                .header(header::COOKIE, &source.cookie)
                .header("x-ott-probe", "present")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(generated_token(response).await, "context-token");

    let calls = generator.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, source.session_id);
    assert_eq!(calls[0].1.method.as_deref(), Some("GET"));
    assert_eq!(calls[0].1.path.as_deref(), Some("/one-time-token/generate"));
    assert_eq!(calls[0].1.query.as_deref(), Some("source=contract"));
    assert_eq!(calls[0].1.headers["x-ott-probe"], "present");
    drop(calls);

    let session = fixture
        .service
        .session(&source.token)
        .await
        .unwrap()
        .unwrap();
    fixture
        .service
        .generate_one_time_token(&session, OneTimeTokenRequestContext::default())
        .await
        .unwrap();
    let calls = generator.calls.lock().await;
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].1, OneTimeTokenRequestContext::default());
}

#[tokio::test]
async fn concurrent_redemption_has_exactly_one_winner() {
    let fixture = fixture(OneTimeTokenConfig::default());
    let source = signup(&fixture, "concurrent").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    let left = fixture.service.clone();
    let right = fixture.service.clone();
    let left_token = token.clone();
    let (left_result, right_result) = tokio::join!(
        async move { left.verify_one_time_token(&left_token).await },
        async move { right.verify_one_time_token(&token).await }
    );
    assert_eq!(
        usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
        1
    );
}

#[tokio::test]
async fn duplicate_custom_tokens_replace_the_binding_with_the_newest_session() {
    let fixture = fixture(fixed_config("duplicate-token", OneTimeTokenStorage::Plain));
    let first = signup(&fixture, "duplicate-first").await;
    let second = signup(&fixture, "duplicate-second").await;
    generated_token(generate(&fixture.app, Some(&first.cookie)).await).await;
    generated_token(generate(&fixture.app, Some(&second.cookie)).await).await;

    let redeemed = fixture
        .service
        .verify_one_time_token("duplicate-token")
        .await
        .unwrap();
    assert_eq!(redeemed.user.id, second.user_id);
    assert!(
        fixture
            .service
            .verify_one_time_token("duplicate-token")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn empty_generator_hash_and_nonpositive_expirations_are_accepted() {
    for expires_in in [Duration::zero(), Duration::minutes(-1)] {
        let fixture = fixture(OneTimeTokenConfig {
            expires_in,
            generator: Some(Arc::new(FixedGenerator::new(""))),
            ..OneTimeTokenConfig::default()
        });
        let source = signup(
            &fixture,
            &format!("nonpositive-{}", expires_in.num_minutes()),
        )
        .await;
        let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
        assert!(token.is_empty());
        assert!(
            fixture
                .service
                .find_verification_value("one-time-token:")
                .await
                .unwrap()
                .is_some()
        );
        assert!(fixture.service.verify_one_time_token("").await.is_err());
    }

    let fixture = fixture(fixed_config(
        "public-token-with-empty-storage-key",
        OneTimeTokenStorage::Custom(Arc::new(EmptyHasher)),
    ));
    let source = signup(&fixture, "empty-hash").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    assert_eq!(token, "public-token-with-empty-storage-key");
    assert!(
        fixture
            .service
            .find_verification_value("one-time-token:")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        fixture
            .service
            .verify_one_time_token(&token)
            .await
            .unwrap()
            .user
            .id,
        source.user_id
    );
}

#[tokio::test]
async fn plugin_storage_composes_with_global_hashing_and_secondary_storage() {
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let fixture = fixture_with(
        fixed_config("composed-token", OneTimeTokenStorage::Hashed),
        |auth| {
            auth.secondary_storage = Some(secondary);
            auth.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        },
    );
    let source = signup(&fixture, "composed").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    let plugin_identifier = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    assert!(
        fixture
            .service
            .find_verification_value(&format!("one-time-token:{plugin_identifier}"))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        fixture
            .service
            .verify_one_time_token(&token)
            .await
            .unwrap()
            .user
            .id,
        source.user_id
    );
    assert!(
        fixture
            .service
            .find_verification_value(&format!("one-time-token:{plugin_identifier}"))
            .await
            .unwrap()
            .is_none()
    );
}
