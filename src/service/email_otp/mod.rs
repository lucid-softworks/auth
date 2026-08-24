pub(crate) mod account;
mod token;

use super::{AuthService, email_password::normalize_email};
use crate::{
    AuthError, EmailOtpConfig, EmailOtpError, EmailOtpMessage, EmailOtpRequestContext, EmailOtpType,
};

impl AuthService {
    pub async fn send_email_otp(
        &self,
        email: &str,
        kind: EmailOtpType,
        context: EmailOtpRequestContext,
    ) -> Result<(), AuthError> {
        let config = self.email_otp_config()?;
        if kind == EmailOtpType::ChangeEmail {
            return Err(EmailOtpError::InvalidOtpType.into());
        }
        let email = normalize_email(email)?;
        let identifier = token::identifier(kind, &email);
        let otp = token::resolve(self, config, &identifier, &email, kind).await?;
        let can_create = kind == EmailOtpType::SignIn && !config.disable_sign_up;
        if self.store.find_user_by_email(&email).await?.is_none() && !can_create {
            self.delete_verification_value(token::PURPOSE, &identifier)
                .await?;
            return Ok(());
        }
        config
            .sender
            .send(EmailOtpMessage { email, otp, kind }, context)
            .await
    }

    pub async fn create_email_otp(
        &self,
        email: &str,
        kind: EmailOtpType,
    ) -> Result<String, AuthError> {
        let email = normalize_email(email)?;
        let config = self.email_otp_config()?;
        let otp = token::generate(config, &email, kind).await?;
        token::store_new(self, config, &token::identifier(kind, &email), &otp).await?;
        Ok(otp)
    }

    pub async fn get_email_otp(
        &self,
        email: &str,
        kind: EmailOtpType,
    ) -> Result<Option<String>, AuthError> {
        let email = normalize_email(email)?;
        token::retrieve(
            self,
            self.email_otp_config()?,
            &token::identifier(kind, &email),
        )
        .await
    }

    pub async fn check_email_otp(
        &self,
        email: &str,
        kind: EmailOtpType,
        otp: &str,
    ) -> Result<(), AuthError> {
        let email = normalize_email(email)?;
        token::check(
            self,
            self.email_otp_config()?,
            &token::identifier(kind, &email),
            otp,
        )
        .await?;
        if self.store.find_user_by_email(&email).await?.is_none() {
            return Err(EmailOtpError::UserNotFound.into());
        }
        Ok(())
    }

    pub(crate) fn email_otp_config(&self) -> Result<&EmailOtpConfig, AuthError> {
        self.configured_email_otp().ok_or_else(|| {
            AuthError::InvalidConfiguration("the email-OTP plugin is not enabled".into())
        })
    }

    pub(super) fn configured_email_otp(&self) -> Option<&EmailOtpConfig> {
        self.plugins
            .find::<crate::EmailOtpPlugin>()
            .map(|plugin| plugin.config.as_ref())
    }

    pub(super) fn email_otp_overrides_verification(&self) -> bool {
        self.configured_email_otp()
            .is_some_and(|config| config.override_default_email_verification)
    }

    pub(super) async fn send_signup_email_otp_if_configured(
        &self,
        user: &crate::AuthUser,
    ) -> Result<(), AuthError> {
        let send = self.configured_email_otp().is_some_and(|config| {
            config.send_verification_on_sign_up && !config.override_default_email_verification
        });
        if send {
            self.send_email_otp(
                &user.email,
                EmailOtpType::EmailVerification,
                EmailOtpRequestContext::default(),
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn deliver_overridden_email_otp(
        &self,
        user: &crate::AuthUser,
    ) -> Result<bool, AuthError> {
        if !self.email_otp_overrides_verification() {
            return Ok(false);
        }
        self.send_email_otp(
            &user.email,
            EmailOtpType::EmailVerification,
            EmailOtpRequestContext::default(),
        )
        .await?;
        Ok(true)
    }
}
