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
            let _ = self.find_verification_value(PURPOSE, "dummy").await?;
            return Ok(());
        };
        let token = random_token();
        let identifier = hash_token(&token);
        let now = Utc::now();
        self.create_verification_record(VerificationValue {
            purpose: PURPOSE.into(),
            identifier,
            payload: json!({ "user_id": user.id }),
            additional_fields: serde_json::Map::new(),
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
            .find_verification_value(PURPOSE, &hash_token(token))
            .await?
            .is_some_and(|value| value.expires_at > Utc::now()))
    }

    pub async fn reset_password(&self, token: &str, password: String) -> Result<(), AuthError> {
        self.validate_new_password(&password).await?;
        let hash = hash_password(password).await?;
        let token_hash = hash_token(token);
        let outcome = if self.config.secondary_storage.is_some()
            && !self.config.verification.store_in_database
        {
            self.consume_secondary_password_reset(&token_hash, hash)
                .await?
        } else {
            let mut outcome = PasswordResetOutcome::InvalidToken;
            for identifier in self
                .verification_identifier_candidates(PURPOSE, &token_hash)
                .await?
            {
                outcome = self
                    .store
                    .consume_password_reset(
                        &identifier,
                        hash.clone(),
                        Utc::now(),
                        self.config.secondary_storage.is_none()
                            && self
                                .config
                                .email_and_password
                                .revoke_sessions_on_password_reset,
                    )
                    .await?;
                if !matches!(outcome, PasswordResetOutcome::InvalidToken) {
                    self.clear_cached_verification(PURPOSE, &token_hash).await?;
                    break;
                }
            }
            outcome
        };
        match outcome {
            PasswordResetOutcome::Reset(user) => {
                if self.config.secondary_storage.is_some()
                    && self
                        .config
                        .email_and_password
                        .revoke_sessions_on_password_reset
                {
                    self.delete_user_sessions_with_hooks(user.id).await?;
                }
                self.refresh_secondary_user_sessions(&user).await?;
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

    async fn consume_secondary_password_reset(
        &self,
        token_hash: &str,
        password_hash: String,
    ) -> Result<PasswordResetOutcome, AuthError> {
        let Some(value) = self
            .consume_verification_record(PURPOSE, token_hash, Utc::now())
            .await?
        else {
            return Ok(PasswordResetOutcome::InvalidToken);
        };
        let user_id = value
            .payload
            .get("user_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .ok_or_else(|| AuthError::Storage("password reset payload is invalid".into()))?;
        if self.store.find_user_by_id(user_id).await?.is_none() {
            return Ok(PasswordResetOutcome::UserNotFound);
        }
        self.store.set_password_hash(user_id, password_hash).await?;
        let user = self
            .store
            .update_user_profile(user_id, crate::UserProfileUpdate::default())
            .await?
            .ok_or_else(|| AuthError::Storage("password reset user disappeared".into()))?;
        Ok(PasswordResetOutcome::Reset(Box::new(user)))
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
