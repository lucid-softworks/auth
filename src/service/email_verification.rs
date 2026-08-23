use super::{AuthService, hash_token, random_token};
use crate::{
    Assurance, AuthError, AuthUser, EmailVerificationOutcome, SessionWithUser, VerificationEmail,
    VerificationValue,
};
use chrono::Utc;
use serde_json::json;

const PURPOSE: &str = "email-verification";

#[derive(Debug, Clone)]
pub struct EmailVerificationResult {
    pub user: AuthUser,
    pub session_token: Option<String>,
}

impl AuthService {
    pub async fn send_verification_email(
        &self,
        email: &str,
        callback_url: Option<&str>,
        session: Option<&SessionWithUser>,
    ) -> Result<(), AuthError> {
        if self.config.email_verification.sender.is_none() {
            return Err(AuthError::VerificationEmailNotEnabled);
        }
        let normalized = super::email_password::normalize_email(email)?;
        if let Some(session) = session {
            if session.user.email != normalized {
                return Err(AuthError::EmailMismatch);
            }
            if session.user.email_verified {
                return Err(AuthError::EmailAlreadyVerified);
            }
            return self
                .deliver_verification_email(session.user.clone(), callback_url)
                .await;
        }

        let started = std::time::Instant::now();
        let user = self.store.find_user_by_email(&normalized).await?;
        let result = match user.filter(|user| !user.email_verified) {
            Some(user) => self.deliver_verification_email(user, callback_url).await,
            None => {
                let _ = hash_token(&random_token());
                Ok(())
            }
        };
        let minimum = std::time::Duration::from_millis(500);
        if let Some(remaining) = minimum.checked_sub(started.elapsed()) {
            tokio::time::sleep(remaining).await;
        }
        result
    }

    pub(super) async fn maybe_send_signup_verification(
        &self,
        user: &AuthUser,
        callback_url: Option<&str>,
    ) -> Result<(), AuthError> {
        let send = self
            .config
            .email_verification
            .send_on_sign_up
            .unwrap_or(self.config.email_and_password.require_email_verification);
        if send && self.config.email_verification.sender.is_some() {
            self.deliver_verification_email(user.clone(), callback_url)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn maybe_send_signin_verification(
        &self,
        user: &AuthUser,
        callback_url: Option<&str>,
    ) -> Result<(), AuthError> {
        if self.config.email_verification.send_on_sign_in
            && self.config.email_verification.sender.is_some()
        {
            self.deliver_verification_email(user.clone(), callback_url)
                .await?;
        }
        Ok(())
    }

    pub async fn verify_email_token(
        &self,
        token: &str,
        current: Option<(&SessionWithUser, &str)>,
    ) -> Result<EmailVerificationResult, AuthError> {
        let outcome = self
            .store
            .consume_email_verification(&hash_token(token), Utc::now())
            .await?;
        let user = match outcome {
            EmailVerificationOutcome::InvalidToken => return Err(AuthError::InvalidToken),
            EmailVerificationOutcome::Expired => return Err(AuthError::TokenExpired),
            EmailVerificationOutcome::UserNotFound => {
                return Err(AuthError::VerificationUserNotFound);
            }
            EmailVerificationOutcome::AlreadyVerified(user) => {
                return Ok(EmailVerificationResult {
                    user,
                    session_token: None,
                });
            }
            EmailVerificationOutcome::Verified(user) => user,
        };
        let session_token = if self
            .config
            .email_verification
            .auto_sign_in_after_verification
        {
            if let Some((_session, token)) =
                current.filter(|(session, _)| session.user.id == user.id)
            {
                Some(token.to_owned())
            } else {
                let assurance = if self.requires_mfa(&user) {
                    Assurance::PasswordPendingPasskey
                } else {
                    Assurance::EmailVerified
                };
                Some(
                    self.create_session(user.clone(), assurance, None, None, None)
                        .await?
                        .token,
                )
            }
        } else {
            None
        };
        Ok(EmailVerificationResult {
            user,
            session_token,
        })
    }

    async fn deliver_verification_email(
        &self,
        user: AuthUser,
        callback_url: Option<&str>,
    ) -> Result<(), AuthError> {
        let sender = self
            .config
            .email_verification
            .sender
            .as_ref()
            .ok_or(AuthError::VerificationEmailNotEnabled)?;
        let token = random_token();
        let token_hash = hash_token(&token);
        let now = Utc::now();
        self.store
            .create_verification(VerificationValue {
                purpose: PURPOSE.into(),
                identifier: token_hash.clone(),
                payload: json!({ "email": user.email }),
                expires_at: now + self.config.email_verification.expires_in,
                created_at: now,
            })
            .await?;
        let email = VerificationEmail {
            url: self.verification_url(&token, callback_url)?,
            user,
            token,
        };
        if let Err(error) = sender.send(email).await {
            let _ = self
                .store
                .consume_verification(PURPOSE, &token_hash, Utc::now())
                .await;
            return Err(error);
        }
        Ok(())
    }

    fn verification_url(
        &self,
        token: &str,
        callback_url: Option<&str>,
    ) -> Result<String, AuthError> {
        let mut url = self.config.base_url.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "a base URL is required to send verification email".into(),
            )
        })?;
        url.set_path(&format!("{}/verify-email", self.config.base_path));
        url.query_pairs_mut()
            .append_pair("token", token)
            .append_pair("callbackURL", callback_url.unwrap_or("/"));
        Ok(url.into())
    }
}
