use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, EmailOtpConfig, EmailOtpMessage, EmailOtpPlugin,
    EmailOtpRequestContext, EmailOtpSender, EmailOtpSignInInput, EmailOtpType,
};
use std::sync::Arc;

struct Sender;

#[async_trait]
impl EmailOtpSender for Sender {
    async fn send(
        &self,
        _message: EmailOtpMessage,
        _context: EmailOtpRequestContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }
}

pub(super) fn register(config: &mut AuthConfig) -> Result<(), AuthError> {
    config.add_plugin(EmailOtpPlugin::new(EmailOtpConfig::new(Arc::new(Sender))))
}

pub(super) async fn assert_redemption_is_atomic(
    service: &Arc<AuthService>,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let email = "postgres-email-otp@example.com";
    let otp = service
        .create_email_otp(email, EmailOtpType::SignIn)
        .await?;
    let left = service.clone();
    let right = service.clone();
    let left_otp = otp.clone();
    let (left_result, right_result) = tokio::join!(
        async move {
            left.sign_in_email_otp(sign_in_input(email, &left_otp))
                .await
        },
        async move { right.sign_in_email_otp(sign_in_input(email, &otp)).await }
    );
    assert_eq!(
        usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM lucid_auth_users WHERE email = $1")
            .bind(email)
            .fetch_one(pool)
            .await?,
        1
    );
    Ok(())
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
