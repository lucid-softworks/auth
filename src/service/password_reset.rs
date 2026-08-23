use super::{AuthService, hash_token, password::hash_password, random_token};
use crate::{
    AuthError, PasswordCredentialChanged, PasswordCredentialSource, PasswordResetEmail,
    PasswordResetOutcome, VerificationValue,
};
use chrono::Utc;
use serde_json::json;

const PURPOSE: &str = "password-reset";

impl AuthService {
    pub async fn request_password_reset(
        &self,
        email: &str,
        redirect_to: Option<&str>,
    ) -> Result<(), AuthError> {
        let sender = self
            .config
            .email_and_password
            .send_reset_password
            .as_ref()
            .ok_or(AuthError::ResetPasswordDisabled)?;
        let email = super::email_password::normalize_email(email)?;
        let Some(user) = self.store.find_user_by_email(&email).await? else {
            let _ = hash_token(&random_token());
            let _ = self.store.find_verification(PURPOSE, "dummy").await?;
            return Ok(());
        };
        let token = random_token();
        let identifier = hash_token(&token);
        let now = Utc::now();
        self.store
            .create_verification(VerificationValue {
                purpose: PURPOSE.into(),
                identifier,
                payload: json!({ "user_id": user.id }),
                expires_at: now
                    + self
                        .config
                        .email_and_password
                        .reset_password_token_expires_in,
                created_at: now,
            })
            .await?;
        let message = PasswordResetEmail {
            url: self.password_reset_url(&token, redirect_to)?,
            user,
            token,
        };
        sender.send(message).await?;
        Ok(())
    }

    pub async fn password_reset_token_valid(&self, token: &str) -> Result<bool, AuthError> {
        Ok(self
            .store
            .find_verification(PURPOSE, &hash_token(token))
            .await?
            .is_some_and(|value| value.expires_at > Utc::now()))
    }

    pub async fn reset_password(&self, token: &str, password: String) -> Result<(), AuthError> {
        self.validate_new_password(&password).await?;
        let hash = hash_password(password).await?;
        match self
            .store
            .consume_password_reset(
                &hash_token(token),
                hash,
                Utc::now(),
                self.config
                    .email_and_password
                    .revoke_sessions_on_password_reset,
            )
            .await?
        {
            PasswordResetOutcome::Reset(user) => {
                self.plugins
                    .password_credential_changed(&PasswordCredentialChanged {
                        user_id: user.id,
                        source: PasswordCredentialSource::PasswordReset,
                    })
                    .await?;
                if let Some(callback) = &self.config.email_and_password.on_password_reset {
                    callback.on_password_reset(*user).await?;
                }
                Ok(())
            }
            PasswordResetOutcome::InvalidToken => Err(AuthError::InvalidPasswordResetToken),
            PasswordResetOutcome::UserNotFound => Err(AuthError::PasswordResetUserNotFound),
        }
    }

    fn password_reset_url(
        &self,
        token: &str,
        redirect_to: Option<&str>,
    ) -> Result<String, AuthError> {
        let mut url = self.config.base_url.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "a base URL is required to send password reset email".into(),
            )
        })?;
        url.set_path(&format!("{}/reset-password/{token}", self.config.base_path));
        url.query_pairs_mut()
            .append_pair("callbackURL", redirect_to.unwrap_or(""));
        Ok(url.into())
    }

    #[cfg(feature = "axum")]
    pub(crate) fn password_reset_redirect(
        &self,
        callback_url: Option<&str>,
        key: &str,
        value: &str,
    ) -> Result<String, AuthError> {
        let mut base = self.config.base_url.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration("a base URL is required for reset redirects".into())
        })?;
        let mut url = match callback_url.filter(|value| !value.is_empty()) {
            Some(callback_url) => base
                .join(callback_url)
                .map_err(|_| AuthError::InvalidCallbackUrl)?,
            None => {
                base.set_path(&format!("{}/error", self.config.base_path));
                base
            }
        };
        url.query_pairs_mut().append_pair(key, value);
        Ok(url.into())
    }
}
