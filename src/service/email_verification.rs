use super::AuthService;
use crate::{AuthError, AuthUser, AuthenticationMethod, SessionWithUser, VerificationEmail};
use chrono::{Duration, Utc};

mod token;
use token::{
    EmailVerificationClaims, decode_email_verification_token, encode_email_verification_token,
};

#[derive(Debug, Clone)]
pub struct EmailVerificationResult {
    pub user: AuthUser,
    pub session_token: Option<String>,
    pub user_in_response: bool,
}

impl AuthService {
    pub async fn send_verification_email(
        &self,
        email: &str,
        callback_url: Option<&str>,
        session: Option<&SessionWithUser>,
    ) -> Result<(), AuthError> {
        if self.config.email_verification.sender.is_none()
            && !self.email_otp_overrides_verification()
        {
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
                let _ = self.create_email_verification_token(&normalized, None, None)?;
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
        self.send_signup_email_otp_if_configured(user).await?;
        let send = self
            .config
            .email_verification
            .send_on_sign_up
            .unwrap_or(self.config.email_and_password.require_email_verification);
        if send
            && (self.config.email_verification.sender.is_some()
                || self.email_otp_overrides_verification())
        {
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
            && (self.config.email_verification.sender.is_some()
                || self.email_otp_overrides_verification())
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
        self.verify_email_token_with_callback(token, current, None)
            .await
    }

    pub(crate) async fn verify_email_token_with_callback(
        &self,
        token: &str,
        current: Option<(&SessionWithUser, &str)>,
        callback_url: Option<&str>,
    ) -> Result<EmailVerificationResult, AuthError> {
        let claims = self.decode_email_verification_token(token)?;
        if claims.update_to.is_some() {
            return self
                .verify_change_email_claims(claims, current, callback_url)
                .await;
        }
        let user = self
            .store
            .find_user_by_email(&claims.email)
            .await?
            .ok_or(AuthError::VerificationUserNotFound)?;
        if user.email_verified {
            self.refresh_secondary_user_sessions(&user).await?;
            return Ok(EmailVerificationResult {
                user,
                session_token: None,
                user_in_response: false,
            });
        }
        let user = self
            .store
            .update_user_email(&user.id, &claims.email, &claims.email, true)
            .await?
            .ok_or(AuthError::VerificationUserNotFound)?;
        self.refresh_secondary_user_sessions(&user).await?;
        let session_token = if self
            .config
            .email_verification
            .auto_sign_in_after_verification
        {
            if let Some((_session, token)) =
                current.filter(|(session, _)| session.user.email == claims.email)
            {
                Some(token.to_owned())
            } else {
                Some(
                    self.create_session(
                        user.clone(),
                        AuthenticationMethod::EmailVerified,
                        None,
                        None,
                        None,
                    )
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
            user_in_response: false,
        })
    }

    async fn verify_change_email_claims(
        &self,
        claims: EmailVerificationClaims,
        current: Option<(&SessionWithUser, &str)>,
        callback_url: Option<&str>,
    ) -> Result<EmailVerificationResult, AuthError> {
        let new_email = claims.update_to.ok_or(AuthError::InvalidToken)?;
        let user = self
            .store
            .find_user_by_email(&claims.email)
            .await?
            .ok_or(AuthError::VerificationUserNotFound)?;
        if current.is_some_and(|(session, _)| session.user.email != claims.email) {
            return Err(AuthError::InvalidUser);
        }
        match claims.request_type.as_deref() {
            Some("change-email-confirmation") => {
                self.deliver_change_verification(&user, &new_email, callback_url)
                    .await?;
                Ok(EmailVerificationResult {
                    user,
                    session_token: None,
                    user_in_response: false,
                })
            }
            Some("change-email-verification") => {
                let session_token = self.change_email_session_token(&user, current).await?;
                let updated = self
                    .store
                    .update_user_email(&user.id, &claims.email, &new_email, true)
                    .await?
                    .ok_or(AuthError::VerificationUserNotFound)?;
                self.refresh_secondary_user_sessions(&updated).await?;
                Ok(EmailVerificationResult {
                    user: updated,
                    session_token: Some(session_token),
                    user_in_response: true,
                })
            }
            _ => {
                let session_token = self.change_email_session_token(&user, current).await?;
                let updated = self
                    .store
                    .update_user_email(&user.id, &claims.email, &new_email, false)
                    .await?
                    .ok_or(AuthError::VerificationUserNotFound)?;
                let token = self.create_email_verification_token_for_duration(
                    &new_email,
                    None,
                    None,
                    Duration::hours(1),
                )?;
                if let Some(sender) = &self.config.email_verification.sender {
                    sender
                        .send(VerificationEmail {
                            user: updated.clone(),
                            url: self.verification_url(&token, callback_url)?,
                            token,
                        })
                        .await?;
                }
                self.refresh_secondary_user_sessions(&updated).await?;
                Ok(EmailVerificationResult {
                    user: updated,
                    session_token: Some(session_token),
                    user_in_response: true,
                })
            }
        }
    }

    async fn change_email_session_token(
        &self,
        user: &AuthUser,
        current: Option<(&SessionWithUser, &str)>,
    ) -> Result<String, AuthError> {
        match current {
            Some((_, token)) => Ok(token.to_owned()),
            None => Ok(self
                .create_session(
                    user.clone(),
                    AuthenticationMethod::EmailVerified,
                    None,
                    None,
                    None,
                )
                .await?
                .token),
        }
    }

    pub(in crate::service) async fn deliver_verification_email(
        &self,
        user: AuthUser,
        callback_url: Option<&str>,
    ) -> Result<(), AuthError> {
        if self.deliver_overridden_email_otp(&user).await? {
            return Ok(());
        }
        let sender = self
            .config
            .email_verification
            .sender
            .as_ref()
            .ok_or(AuthError::VerificationEmailNotEnabled)?;
        let token = self.create_email_verification_token(&user.email, None, None)?;
        let email = VerificationEmail {
            url: self.verification_url(&token, callback_url)?,
            user,
            token,
        };
        sender.send(email).await
    }

    pub(super) fn verification_url(
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

    pub(super) fn create_email_verification_token(
        &self,
        email: &str,
        update_to: Option<&str>,
        request_type: Option<&str>,
    ) -> Result<String, AuthError> {
        self.create_email_verification_token_for_duration(
            email,
            update_to,
            request_type,
            self.config.email_verification.expires_in,
        )
    }

    fn create_email_verification_token_for_duration(
        &self,
        email: &str,
        update_to: Option<&str>,
        request_type: Option<&str>,
        expires_in: Duration,
    ) -> Result<String, AuthError> {
        encode_email_verification_token(
            &self.config.secret,
            email,
            update_to,
            request_type,
            Utc::now(),
            expires_in,
        )
    }

    fn decode_email_verification_token(
        &self,
        token: &str,
    ) -> Result<EmailVerificationClaims, AuthError> {
        decode_email_verification_token(&self.config.secret, token, Utc::now())
    }
}
