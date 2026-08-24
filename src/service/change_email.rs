use super::{AuthService, hash_token, random_token};
use crate::{
    AuthError, AuthUser, ChangeEmailConfirmation, SessionWithUser, VerificationEmail,
    VerificationValue,
};
use chrono::Utc;
use serde_json::json;

pub(super) const CHANGE_CONFIRMATION_PURPOSE: &str = "change-email-confirmation";
pub(super) const CHANGE_VERIFICATION_PURPOSE: &str = "change-email-verification";

impl AuthService {
    pub async fn change_email(
        &self,
        session: &SessionWithUser,
        new_email: &str,
        callback_url: Option<&str>,
    ) -> Result<Option<AuthUser>, AuthError> {
        let config = &self.config.user.change_email;
        if !config.enabled {
            return Err(AuthError::ChangeEmailDisabled);
        }
        let new_email = super::email_password::normalize_email(new_email)?;
        if new_email == session.user.email {
            return Err(AuthError::EmailIsSame);
        }
        let can_update = !session.user.email_verified && config.update_email_without_verification;
        let can_verify = self.config.email_verification.sender.is_some();
        let can_confirm = can_verify
            && session.user.email_verified
            && config.send_change_email_confirmation.is_some();
        if !can_update && !can_confirm && !can_verify {
            return Err(AuthError::VerificationEmailNotEnabled);
        }
        if self.store.find_user_by_email(&new_email).await?.is_some() {
            let _ = hash_token(&random_token());
            return Ok(None);
        }
        if can_update {
            let mut candidate = session.user.clone();
            candidate.email = new_email;
            candidate.email_verified = false;
            let candidate = self.prepare_user_update(&session.user, candidate).await?;
            let updated = self
                .store
                .update_user_email(
                    session.user.id,
                    &session.user.email,
                    &candidate.email,
                    candidate.email_verified,
                )
                .await?
                .ok_or(AuthError::InvalidSession)?;
            self.after_database_update(&crate::DatabaseRecord::User(updated.clone()))
                .await?;
            if can_verify {
                self.deliver_verification_email(updated.clone(), callback_url)
                    .await?;
            }
            return Ok(Some(updated));
        }
        if can_confirm {
            self.deliver_change_confirmation(&session.user, &new_email, callback_url)
                .await?;
        } else {
            self.deliver_change_verification(&session.user, &new_email, callback_url)
                .await?;
        }
        Ok(None)
    }

    async fn deliver_change_confirmation(
        &self,
        user: &AuthUser,
        new_email: &str,
        callback_url: Option<&str>,
    ) -> Result<(), AuthError> {
        let sender = self
            .config
            .user
            .change_email
            .send_change_email_confirmation
            .as_ref()
            .ok_or(AuthError::VerificationEmailNotEnabled)?;
        let (token, token_hash) = self
            .create_change_token(CHANGE_CONFIRMATION_PURPOSE, user, new_email)
            .await?;
        let confirmation = ChangeEmailConfirmation {
            user: user.clone(),
            new_email: new_email.into(),
            url: self.verification_url(&token, callback_url)?,
            token,
        };
        if let Err(error) = sender.send(confirmation).await {
            let _ = self
                .consume_verification_record(CHANGE_CONFIRMATION_PURPOSE, &token_hash, Utc::now())
                .await;
            return Err(error);
        }
        Ok(())
    }

    pub(super) async fn deliver_change_verification(
        &self,
        user: &AuthUser,
        new_email: &str,
        callback_url: Option<&str>,
    ) -> Result<(), AuthError> {
        let sender = self
            .config
            .email_verification
            .sender
            .as_ref()
            .ok_or(AuthError::VerificationEmailNotEnabled)?;
        let (token, token_hash) = self
            .create_change_token(CHANGE_VERIFICATION_PURPOSE, user, new_email)
            .await?;
        let mut target = user.clone();
        target.email = new_email.into();
        let email = VerificationEmail {
            user: target,
            url: self.verification_url(&token, callback_url)?,
            token,
        };
        if let Err(error) = sender.send(email).await {
            let _ = self
                .consume_verification_record(CHANGE_VERIFICATION_PURPOSE, &token_hash, Utc::now())
                .await;
            return Err(error);
        }
        Ok(())
    }

    async fn create_change_token(
        &self,
        purpose: &str,
        user: &AuthUser,
        new_email: &str,
    ) -> Result<(String, String), AuthError> {
        let token = random_token();
        let token_hash = hash_token(&token);
        let now = Utc::now();
        self.create_verification_record(VerificationValue {
            purpose: purpose.into(),
            identifier: token_hash.clone(),
            payload: json!({
                "userId": user.id,
                "email": user.email,
                "newEmail": new_email,
            }),
            additional_fields: serde_json::Map::new(),
            expires_at: now + self.config.email_verification.expires_in,
            created_at: now,
        })
        .await?;
        Ok((token, token_hash))
    }
}
