use super::{AuthService, token};
use crate::{
    AuthError, AuthUser, AuthenticationMethod, DatabaseRecord, EmailOtpError, EmailOtpMessage,
    EmailOtpRequestContext, EmailOtpSignInInput, EmailOtpType, EmailOtpVerification,
    PasswordCredentialChanged, PasswordCredentialSource, SessionWithUser, SignInResult,
    UserProfileUpdate,
};
use chrono::Utc;
use serde_json::{Map, Value};

impl AuthService {
    pub async fn verify_email_otp(
        &self,
        email: &str,
        otp: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<EmailOtpVerification, AuthError> {
        let email = super::super::email_password::normalize_email(email)?;
        token::consume(
            self,
            self.email_otp_config()?,
            &token::identifier(EmailOtpType::EmailVerification, &email),
            otp,
        )
        .await?;
        let user = self
            .store
            .find_user_by_email(&email)
            .await?
            .ok_or(EmailOtpError::UserNotFound)?;
        let user = self.mark_email_verified(user).await?;
        let session = if self
            .config
            .email_verification
            .auto_sign_in_after_verification
        {
            Some(
                self.create_session(
                    user.clone(),
                    AuthenticationMethod::EmailVerified,
                    None,
                    ip_address,
                    user_agent,
                )
                .await?,
            )
        } else {
            None
        };
        Ok(EmailOtpVerification { user, session })
    }

    pub async fn sign_in_email_otp(
        &self,
        input: EmailOtpSignInInput,
    ) -> Result<SignInResult, AuthError> {
        let email = super::super::email_password::normalize_email(&input.email)?;
        let config = self.email_otp_config()?;
        token::consume(
            self,
            config,
            &token::identifier(EmailOtpType::SignIn, &email),
            &input.otp,
        )
        .await?;
        let user = match self.store.find_user_by_email(&email).await? {
            Some(user) if user.email_verified => user,
            Some(user) => self
                .store
                .promote_email_owner(&user.id, Utc::now())
                .await?
                .ok_or(EmailOtpError::InvalidOtp)?,
            None if config.disable_sign_up => return Err(EmailOtpError::InvalidOtp.into()),
            None => {
                self.create_email_otp_user(email, input.name, input.image, input.additional_fields)
                    .await?
            }
        };
        self.create_session(
            user,
            AuthenticationMethod::EmailVerified,
            None,
            input.ip_address,
            input.user_agent,
        )
        .await
    }

    pub async fn request_password_reset_email_otp(
        &self,
        email: &str,
        context: EmailOtpRequestContext,
    ) -> Result<(), AuthError> {
        let email = super::super::email_password::normalize_email(email)?;
        let config = self.email_otp_config()?;
        let identifier = token::identifier(EmailOtpType::ForgetPassword, &email);
        let otp = token::resolve(
            self,
            config,
            &identifier,
            &email,
            EmailOtpType::ForgetPassword,
        )
        .await?;
        if self.store.find_user_by_email(&email).await?.is_none() {
            self.delete_verification_value(&identifier).await?;
            return Ok(());
        }
        config
            .sender
            .send(
                EmailOtpMessage {
                    email,
                    otp,
                    kind: EmailOtpType::ForgetPassword,
                },
                context,
            )
            .await
    }

    pub async fn reset_password_email_otp(
        &self,
        email: &str,
        otp: &str,
        password: String,
    ) -> Result<(), AuthError> {
        let email = super::super::email_password::normalize_email(email)?;
        self.validate_new_password(&password).await?;
        token::consume(
            self,
            self.email_otp_config()?,
            &token::identifier(EmailOtpType::ForgetPassword, &email),
            otp,
        )
        .await?;
        let mut user = self
            .store
            .find_user_by_email(&email)
            .await?
            .ok_or(EmailOtpError::UserNotFound)?;
        let password_hash = self.hash_password(password).await?;
        self.set_password_hash_with_database_id(&user.id, password_hash)
            .await?;
        if !user.email_verified {
            user = self.mark_email_verified(user).await?;
        } else {
            user = self
                .store
                .update_user_profile(&user.id, UserProfileUpdate::default())
                .await?
                .ok_or(EmailOtpError::UserNotFound)?;
            self.refresh_secondary_user_sessions(&user).await?;
        }
        if self
            .config
            .email_and_password
            .revoke_sessions_on_password_reset
        {
            self.delete_user_sessions_with_hooks(&user.id).await?;
        }
        self.plugins
            .password_credential_changed(&PasswordCredentialChanged {
                user_id: user.id.clone(),
                source: PasswordCredentialSource::PasswordReset,
            })
            .await?;
        if let Some(callback) = &self.config.email_and_password.on_password_reset {
            callback.on_password_reset(user).await?;
        }
        Ok(())
    }

    pub async fn request_email_change_email_otp(
        &self,
        session: &SessionWithUser,
        new_email: &str,
        current_otp: Option<&str>,
        context: EmailOtpRequestContext,
    ) -> Result<(), AuthError> {
        self.require_email_otp_sensitive_session(session).await?;
        let config = self.email_otp_config()?;
        if !config.change_email.enabled {
            return Err(EmailOtpError::ChangeEmailDisabled.into());
        }
        let email = session.user.email.to_lowercase();
        let new_email = super::super::email_password::normalize_email(new_email)?;
        if email == new_email {
            return Err(EmailOtpError::EmailIsSame.into());
        }
        if config.change_email.verify_current_email {
            let current_otp = current_otp.ok_or(EmailOtpError::CurrentEmailOtpRequired)?;
            token::consume(
                self,
                config,
                &token::identifier(EmailOtpType::EmailVerification, &email),
                current_otp,
            )
            .await?;
        }
        let joined = format!("{email}-{new_email}");
        let identifier = token::identifier(EmailOtpType::ChangeEmail, &joined);
        let otp = token::generate(config, &new_email, EmailOtpType::ChangeEmail).await?;
        token::store_new(self, config, &identifier, &otp).await?;
        if self.store.find_user_by_email(&new_email).await?.is_some() {
            self.delete_verification_value(&identifier).await?;
            return Ok(());
        }
        config
            .sender
            .send(
                EmailOtpMessage {
                    email: new_email,
                    otp,
                    kind: EmailOtpType::ChangeEmail,
                },
                context,
            )
            .await
    }

    pub async fn change_email_email_otp(
        &self,
        session: &SessionWithUser,
        new_email: &str,
        otp: &str,
    ) -> Result<AuthUser, AuthError> {
        self.require_email_otp_sensitive_session(session).await?;
        let config = self.email_otp_config()?;
        if !config.change_email.enabled {
            return Err(EmailOtpError::ChangeEmailDisabled.into());
        }
        let email = session.user.email.to_lowercase();
        let new_email = super::super::email_password::normalize_email(new_email)?;
        if email == new_email {
            return Err(EmailOtpError::EmailIsSame.into());
        }
        let joined = format!("{email}-{new_email}");
        token::consume(
            self,
            config,
            &token::identifier(EmailOtpType::ChangeEmail, &joined),
            otp,
        )
        .await?;
        if self.store.find_user_by_email(&email).await?.is_none() {
            return Err(EmailOtpError::UserNotFound.into());
        }
        if self.store.find_user_by_email(&new_email).await?.is_some() {
            return Err(EmailOtpError::EmailAlreadyInUse.into());
        }
        let mut candidate = session.user.clone();
        candidate.email.clone_from(&new_email);
        candidate.email_verified = true;
        let candidate = self.prepare_user_update(&session.user, candidate).await?;
        let updated = self
            .store
            .update_user_email(&session.user.id, &email, &candidate.email, true)
            .await?
            .ok_or(EmailOtpError::UserNotFound)?;
        self.after_database_update(&DatabaseRecord::User(updated.clone()))
            .await?;
        Ok(updated)
    }

    async fn create_email_otp_user(
        &self,
        email: String,
        name: Option<String>,
        image: Option<String>,
        additional_fields: Map<String, Value>,
    ) -> Result<AuthUser, AuthError> {
        let now = Utc::now();
        let user = self
            .prepare_user_create(AuthUser {
                id: String::new(),
                username: None,
                display_username: None,
                name: name.unwrap_or_default(),
                email,
                email_verified: true,
                image,
                additional_fields,
                role: self.default_user_role(),
                is_anonymous: false,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            })
            .await?;
        let user = self.store.create_user_without_account(user).await?;
        self.finish_user_create(&user).await?;
        Ok(user)
    }

    async fn mark_email_verified(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        let mut candidate = user.clone();
        candidate.email_verified = true;
        let candidate = self.prepare_user_update(&user, candidate).await?;
        let updated = self
            .store
            .update_user_email(&user.id, &user.email, &candidate.email, true)
            .await?
            .ok_or(EmailOtpError::UserNotFound)?;
        self.after_database_update(&DatabaseRecord::User(updated.clone()))
            .await?;
        Ok(updated)
    }

    async fn require_email_otp_sensitive_session(
        &self,
        session: &SessionWithUser,
    ) -> Result<(), AuthError> {
        super::super::account_lifecycle::require_account_session(session)?;
        if self.config.session_fresh_age != chrono::Duration::zero()
            && session.session.created_at + self.config.session_fresh_age <= Utc::now()
        {
            return Err(AuthError::SessionNotFresh);
        }
        self.plugins
            .authorize_sensitive(&crate::SensitiveOperation {
                session,
                operation: "email-otp.change-email",
            })
            .await
    }
}
