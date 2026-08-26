use super::AuthService;
use crate::{
    AuthError, PasswordCredentialChanged, PasswordCredentialSource, PasswordResetEmail,
    VerificationValue,
};
use chrono::Utc;
use rand::RngExt;

const RESET_IDENTIFIER_PREFIX: &str = "reset-password:";
const TOKEN_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

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
            let _ = reset_token();
            let _ = self
                .find_verification_value("dummy-verification-token")
                .await?;
            return Ok(());
        };
        let token = reset_token();
        let now = Utc::now();
        self.create_verification_record(VerificationValue::new(
            format!("{RESET_IDENTIFIER_PREFIX}{token}"),
            user.id.to_string(),
            now + self
                .config
                .email_and_password
                .reset_password_token_expires_in,
        ))
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
            .find_verification_value(&format!("{RESET_IDENTIFIER_PREFIX}{token}"))
            .await?
            .is_some_and(|value| value.expires_at >= Utc::now()))
    }

    pub async fn reset_password(&self, token: &str, password: String) -> Result<(), AuthError> {
        self.validate_new_password(&password).await?;
        let Some(value) = self
            .consume_verification_record(&format!("{RESET_IDENTIFIER_PREFIX}{token}"), Utc::now())
            .await?
        else {
            return Err(AuthError::InvalidPasswordResetToken);
        };
        let user_id = uuid::Uuid::parse_str(&value.value)
            .map_err(|_| AuthError::Storage("password reset value is invalid".into()))?;
        if self.store.find_user_by_id(user_id).await?.is_none() {
            return Err(AuthError::PasswordResetUserNotFound);
        }
        let password_hash = self.hash_password(password).await?;
        self.store.set_password_hash(user_id, password_hash).await?;
        let user = self
            .store
            .update_user_profile(user_id, crate::UserProfileUpdate::default())
            .await?
            .ok_or_else(|| AuthError::Storage("password reset user disappeared".into()))?;
        if self
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
            callback.on_password_reset(user).await?;
        }
        Ok(())
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

fn reset_token() -> String {
    let mut rng = rand::rng();
    (0..24)
        .map(|_| TOKEN_ALPHABET[rng.random_range(0..TOKEN_ALPHABET.len())] as char)
        .collect()
}
