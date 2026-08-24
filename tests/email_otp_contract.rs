use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, EmailOtpConfig, EmailOtpError, EmailOtpMessage,
    EmailOtpPlugin, EmailOtpRequestContext, EmailOtpResendStrategy, EmailOtpSender,
    EmailOtpSignInInput, EmailOtpStorage, EmailOtpType, MemoryStore, NewPasswordUser,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct Sender {
    messages: Mutex<Vec<EmailOtpMessage>>,
}

#[async_trait]
impl EmailOtpSender for Sender {
    async fn send(
        &self,
        message: EmailOtpMessage,
        _context: EmailOtpRequestContext,
    ) -> Result<(), AuthError> {
        self.messages.lock().await.push(message);
        Ok(())
    }
}

fn service(configure: impl FnOnce(&mut EmailOtpConfig)) -> (Arc<AuthService>, Arc<Sender>) {
    let sender = Arc::new(Sender::default());
    let mut config = AuthConfig::new([31_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    let mut email_otp = EmailOtpConfig::new(sender.clone());
    email_otp.rate_limit_max = 100;
    configure(&mut email_otp);
    config.add_plugin(EmailOtpPlugin::new(email_otp)).unwrap();
    (
        Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config)),
        sender,
    )
}

async fn provision(service: &AuthService, username: &str, email: &str) {
    service
        .provision_password_user(NewPasswordUser {
            username: username.into(),
            name: username.into(),
            email: Some(email.into()),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn descriptor_and_defaults_match_better_auth_1_7_1() {
    let (service, _) = service(|_| {});
    let descriptor = service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "email-otp")
        .unwrap();
    assert_eq!(descriptor.client.unwrap().factory, "emailOTPClient");
    assert_eq!(descriptor.endpoints.len(), 9);
    assert!(descriptor.endpoints.iter().any(|endpoint| {
        endpoint.path == "/forget-password/email-otp"
            && endpoint.client_method == "forgetPassword.emailOtp"
    }));
}

#[tokio::test]
async fn sends_are_enumeration_safe_and_sign_in_can_create_a_user() {
    let (service, sender) = service(|_| {});
    provision(&service, "known_user", "known@example.com").await;

    service
        .send_email_otp(
            "missing@example.com",
            EmailOtpType::EmailVerification,
            EmailOtpRequestContext::default(),
        )
        .await
        .unwrap();
    assert!(sender.messages.lock().await.is_empty());

    service
        .send_email_otp(
            "new@example.com",
            EmailOtpType::SignIn,
            EmailOtpRequestContext::default(),
        )
        .await
        .unwrap();
    let otp = sender.messages.lock().await[0].otp.clone();
    let signed_in = service
        .sign_in_email_otp(EmailOtpSignInInput {
            email: "new@example.com".into(),
            otp,
            name: Some("New User".into()),
            image: None,
            additional_fields: serde_json::Map::new(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();
    assert_eq!(signed_in.session.user.email, "new@example.com");
    assert!(signed_in.session.user.email_verified);
}

#[tokio::test]
async fn attempt_budget_and_successful_redemption_are_single_use() {
    let (service, _) = service(|_| {});
    let otp = service
        .create_email_otp("race@example.com", EmailOtpType::SignIn)
        .await
        .unwrap();
    for _ in 0..3 {
        let error = service
            .sign_in_email_otp(sign_in_input("race@example.com", "wrong"))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AuthError::EmailOtp(EmailOtpError::InvalidOtp)
        ));
    }
    let exhausted = service
        .sign_in_email_otp(sign_in_input("race@example.com", &otp))
        .await
        .unwrap_err();
    assert!(matches!(
        exhausted,
        AuthError::EmailOtp(EmailOtpError::TooManyAttempts)
    ));

    let otp = service
        .create_email_otp("winner@example.com", EmailOtpType::SignIn)
        .await
        .unwrap();
    let left = service.clone();
    let right = service.clone();
    let left_otp = otp.clone();
    let (left_result, right_result) = tokio::join!(
        async move {
            left.sign_in_email_otp(sign_in_input("winner@example.com", &left_otp))
                .await
        },
        async move {
            right
                .sign_in_email_otp(sign_in_input("winner@example.com", &otp))
                .await
        }
    );
    assert_eq!(
        usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
        1
    );

    provision(&service, "check_user", "check@example.com").await;
    service
        .create_email_otp("check@example.com", EmailOtpType::EmailVerification)
        .await
        .unwrap();
    for _ in 0..3 {
        let error = service
            .check_email_otp(
                "check@example.com",
                EmailOtpType::EmailVerification,
                "wrong",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AuthError::EmailOtp(EmailOtpError::InvalidOtp)
        ));
    }
    let exhausted = service
        .check_email_otp(
            "check@example.com",
            EmailOtpType::EmailVerification,
            "wrong",
        )
        .await
        .unwrap_err();
    assert!(matches!(
        exhausted,
        AuthError::EmailOtp(EmailOtpError::TooManyAttempts)
    ));
}

fn sign_in_input(email: &str, otp: &str) -> EmailOtpSignInInput {
    EmailOtpSignInInput {
        email: email.into(),
        otp: otp.into(),
        name: None,
        image: None,
        additional_fields: serde_json::Map::new(),
        ip_address: None,
        user_agent: None,
    }
}

#[tokio::test]
async fn storage_and_resend_profiles_match_recoverability() {
    let (plain, _) = service(|config| {
        config.resend_strategy = EmailOtpResendStrategy::Reuse;
    });
    let first = plain
        .create_email_otp("reuse@example.com", EmailOtpType::SignIn)
        .await
        .unwrap();
    plain
        .send_email_otp(
            "reuse@example.com",
            EmailOtpType::SignIn,
            EmailOtpRequestContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        plain
            .get_email_otp("reuse@example.com", EmailOtpType::SignIn)
            .await
            .unwrap(),
        Some(first)
    );

    let (hashed, _) = service(|config| config.storage = EmailOtpStorage::Hashed);
    hashed
        .create_email_otp("hashed@example.com", EmailOtpType::SignIn)
        .await
        .unwrap();
    let error = hashed
        .get_email_otp("hashed@example.com", EmailOtpType::SignIn)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AuthError::EmailOtp(EmailOtpError::HashedOtpUnavailable)
    ));

    let (encrypted, _) = service(|config| config.storage = EmailOtpStorage::Encrypted);
    let otp = encrypted
        .create_email_otp("encrypted@example.com", EmailOtpType::SignIn)
        .await
        .unwrap();
    assert_eq!(
        encrypted
            .get_email_otp("encrypted@example.com", EmailOtpType::SignIn)
            .await
            .unwrap(),
        Some(otp)
    );
}

#[tokio::test]
async fn plugin_can_send_on_signup_and_override_core_verification_delivery() {
    let sender = Arc::new(Sender::default());
    let mut config = AuthConfig::new([32_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.email_and_password.require_email_verification = true;
    let mut email_otp = EmailOtpConfig::new(sender.clone());
    email_otp.override_default_email_verification = true;
    config.add_plugin(EmailOtpPlugin::new(email_otp)).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);

    let signed_up = service
        .sign_up_email(
            lucid_auth::EmailSignUpInput {
                name: "Verification User".into(),
                email: "verify@example.com".into(),
                password: "correct horse battery staple".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                username: None,
                display_username: None,
                additional_fields: serde_json::Map::new(),
            },
            None,
            None,
        )
        .await
        .unwrap();
    assert!(signed_up.token.is_none());
    let messages = sender.messages.lock().await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].kind, EmailOtpType::EmailVerification);
    drop(messages);

    service
        .send_verification_email("verify@example.com", None, None)
        .await
        .unwrap();
    assert_eq!(sender.messages.lock().await.len(), 2);
}
