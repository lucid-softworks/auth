use super::*;
use lucid_auth::{VerificationIdentifierHasher, VerificationIdentifierStorage};

struct FailingResetCallback;

#[async_trait]
impl PasswordResetCallback for FailingResetCallback {
    async fn on_password_reset(&self, _user: lucid_auth::AuthUser) -> Result<(), AuthError> {
        Err(AuthError::Worker)
    }
}

#[derive(Debug)]
struct RecordingResetHasher {
    inputs: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl VerificationIdentifierHasher for RecordingResetHasher {
    async fn hash(&self, identifier: &str) -> Result<String, AuthError> {
        self.inputs.lock().await.push(identifier.to_owned());
        Ok(format!("stored:{identifier}"))
    }
}

#[tokio::test]
async fn reset_prefix_override_transforms_the_complete_identifier_once_per_operation() {
    let inputs = Arc::new(Mutex::new(Vec::new()));
    let (app, service, fixture) = application(|config| {
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        config.verification.store_identifier.overrides.push((
            "reset-password:".into(),
            VerificationIdentifierStorage::Custom(Arc::new(RecordingResetHasher {
                inputs: inputs.clone(),
            })),
        ));
    });
    signup(&app, "identifier-mode@example.com").await;
    request_reset(&app, "identifier-mode@example.com", None).await;
    let token = fixture.sent.lock().await[0].token.clone();
    let complete = format!("reset-password:{token}");
    assert_eq!(inputs.lock().await.as_slice(), [complete.as_str()]);

    service
        .reset_password(&token, "replacement through custom identifier".into())
        .await
        .unwrap();
    assert_eq!(
        inputs.lock().await.as_slice(),
        [complete.as_str(), complete.as_str()]
    );
}

#[tokio::test]
async fn reset_callback_runs_before_optional_session_revocation() {
    let (app, service, fixture) = application(|config| {
        config.email_and_password.revoke_sessions_on_password_reset = true;
        config.email_and_password.on_password_reset = Some(Arc::new(FailingResetCallback));
    });
    let session_token = signup(&app, "callback-order@example.com").await;
    request_reset(&app, "callback-order@example.com", None).await;
    let reset_token = fixture.sent.lock().await[0].token.clone();

    assert!(matches!(
        service
            .reset_password(&reset_token, "replacement after callback failure".into())
            .await,
        Err(AuthError::Worker)
    ));
    assert!(service.session(&session_token).await.unwrap().is_some());
    assert!(
        service
            .sign_in_email(
                "callback-order@example.com",
                "replacement after callback failure".into(),
                None,
                None,
                None,
                None,
            )
            .await
            .is_ok()
    );
}
