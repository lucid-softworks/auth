use super::{AuthService, hash_token, random_token};
use crate::{
    AuthError, AuthUser, AuthenticationMethod, EmailVerificationOutcome, SessionWithUser,
    VerificationEmail, VerificationValue,
};
use chrono::Utc;
use serde_json::json;

const PURPOSE: &str = "email-verification";

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
        self.verify_email_token_with_callback(token, current, None)
            .await
    }

    pub(crate) async fn verify_email_token_with_callback(
        &self,
        token: &str,
        current: Option<(&SessionWithUser, &str)>,
        callback_url: Option<&str>,
    ) -> Result<EmailVerificationResult, AuthError> {
        if let Some(result) = self
            .consume_change_email_token(token, current, callback_url)
            .await?
        {
            return Ok(result);
        }
        let token_hash = hash_token(token);
        let outcome = self.consume_email_verification_token(&token_hash).await?;
        let user = match outcome {
            EmailVerificationOutcome::InvalidToken => return Err(AuthError::InvalidToken),
            EmailVerificationOutcome::Expired => return Err(AuthError::TokenExpired),
            EmailVerificationOutcome::UserNotFound => {
                return Err(AuthError::VerificationUserNotFound);
            }
            EmailVerificationOutcome::AlreadyVerified(user) => {
                self.refresh_secondary_user_sessions(&user).await?;
                return Ok(EmailVerificationResult {
                    user,
                    session_token: None,
                    user_in_response: false,
                });
            }
            EmailVerificationOutcome::Verified(user) => user,
        };
        self.refresh_secondary_user_sessions(&user).await?;
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

    async fn consume_email_verification_token(
        &self,
        token_hash: &str,
    ) -> Result<EmailVerificationOutcome, AuthError> {
        if self.config.secondary_storage.is_some() && !self.config.verification.store_in_database {
            return self.consume_secondary_email_verification(token_hash).await;
        }
        let mut outcome = EmailVerificationOutcome::InvalidToken;
        for identifier in self
            .verification_identifier_candidates(PURPOSE, token_hash)
            .await?
        {
            outcome = self
                .store
                .consume_email_verification(&identifier, Utc::now())
                .await?;
            if !matches!(outcome, EmailVerificationOutcome::InvalidToken) {
                self.clear_cached_verification(PURPOSE, token_hash).await?;
                break;
            }
        }
        Ok(outcome)
    }

    async fn consume_secondary_email_verification(
        &self,
        token_hash: &str,
    ) -> Result<EmailVerificationOutcome, AuthError> {
        let Some(found) = self.find_verification_value(PURPOSE, token_hash).await? else {
            return Ok(EmailVerificationOutcome::InvalidToken);
        };
        let now = Utc::now();
        let Some(value) = self
            .consume_verification_record(PURPOSE, token_hash, now)
            .await?
        else {
            return Ok(if found.expires_at <= now {
                EmailVerificationOutcome::Expired
            } else {
                EmailVerificationOutcome::InvalidToken
            });
        };
        let email = value
            .payload
            .get("email")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AuthError::Storage("email verification payload is invalid".into()))?;
        let Some(user) = self.store.find_user_by_email(email).await? else {
            return Ok(EmailVerificationOutcome::UserNotFound);
        };
        if user.email_verified {
            return Ok(EmailVerificationOutcome::AlreadyVerified(user));
        }
        self.store
            .update_user_email(user.id, email, email, true)
            .await?
            .map(EmailVerificationOutcome::Verified)
            .ok_or_else(|| AuthError::Storage("email verification user disappeared".into()))
    }

    async fn consume_change_email_token(
        &self,
        token: &str,
        current: Option<(&SessionWithUser, &str)>,
        callback_url: Option<&str>,
    ) -> Result<Option<EmailVerificationResult>, AuthError> {
        let token_hash = hash_token(token);
        for purpose in [
            super::change_email::CHANGE_CONFIRMATION_PURPOSE,
            super::change_email::CHANGE_VERIFICATION_PURPOSE,
        ] {
            let Some(found) = self
                .find_verification_record(purpose, &token_hash, false)
                .await?
            else {
                continue;
            };
            if found.expires_at <= Utc::now() {
                let _ = self
                    .consume_verification_record(purpose, &token_hash, Utc::now())
                    .await;
                return Err(AuthError::TokenExpired);
            }
            let (user, email, new_email) = self.change_email_token_user(&found, current).await?;
            let value = self
                .consume_verification_record(purpose, &token_hash, Utc::now())
                .await?
                .ok_or_else(|| {
                    if found.expires_at <= Utc::now() {
                        AuthError::TokenExpired
                    } else {
                        AuthError::InvalidToken
                    }
                })?;
            change_email_payload(&value)?;
            if purpose == super::change_email::CHANGE_CONFIRMATION_PURPOSE {
                self.deliver_change_verification(&user, &new_email, callback_url)
                    .await?;
                return Ok(Some(EmailVerificationResult {
                    user,
                    session_token: None,
                    user_in_response: false,
                }));
            }
            let updated = self
                .store
                .update_user_email(user.id, &email, &new_email, true)
                .await?
                .ok_or(AuthError::VerificationUserNotFound)?;
            self.refresh_secondary_user_sessions(&updated).await?;
            let session_token = match current {
                Some((_, token)) => Some(token.to_owned()),
                None => Some(
                    self.create_session(
                        updated.clone(),
                        AuthenticationMethod::EmailVerified,
                        None,
                        None,
                        None,
                    )
                    .await?
                    .token,
                ),
            };
            return Ok(Some(EmailVerificationResult {
                user: updated,
                session_token,
                user_in_response: true,
            }));
        }
        Ok(None)
    }

    async fn change_email_token_user(
        &self,
        value: &VerificationValue,
        current: Option<(&SessionWithUser, &str)>,
    ) -> Result<(AuthUser, String, String), AuthError> {
        let (user_id, email, new_email) = change_email_payload(value)?;
        let user = self
            .store
            .find_user_by_id(user_id)
            .await?
            .filter(|user| user.email == email)
            .ok_or(AuthError::VerificationUserNotFound)?;
        if current.is_some_and(|(session, _)| session.user.email != email) {
            return Err(AuthError::InvalidUser);
        }
        Ok((user, email, new_email))
    }

    pub(super) async fn deliver_verification_email(
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
        self.create_verification_record(VerificationValue {
            purpose: PURPOSE.into(),
            identifier: token_hash.clone(),
            payload: json!({ "email": user.email }),
            additional_fields: serde_json::Map::new(),
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
                .consume_verification_record(PURPOSE, &token_hash, Utc::now())
                .await;
            return Err(error);
        }
        Ok(())
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
}

fn change_email_payload(
    value: &VerificationValue,
) -> Result<(uuid::Uuid, String, String), AuthError> {
    let user_id = value
        .payload
        .get("userId")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok());
    let email = value
        .payload
        .get("email")
        .and_then(serde_json::Value::as_str);
    let new_email = value
        .payload
        .get("newEmail")
        .and_then(serde_json::Value::as_str);
    match (user_id, email, new_email) {
        (Some(user_id), Some(email), Some(new_email)) => {
            Ok((user_id, email.into(), new_email.into()))
        }
        _ => Err(AuthError::InvalidToken),
    }
}
