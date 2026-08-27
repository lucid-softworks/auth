use super::{AuthService, token};
use crate::{
    AuthError, AuthUser, AuthenticationMethod, DatabaseRecord, PasswordCredentialChanged,
    PasswordCredentialSource, PhoneNumberError, PhoneNumberMessage, PhoneNumberRequestContext,
    PhoneNumberSignInInput, PhoneNumberVerification, PhoneNumberVerified, PhoneNumberVerifyInput,
    PhoneNumberWriteOutcome, SessionWithUser, UserProfileUpdate,
};
use chrono::Utc;
use serde_json::{Map, Value, json};

const PHONE_NUMBER: &str = "phoneNumber";
const PHONE_NUMBER_VERIFIED: &str = "phoneNumberVerified";

impl AuthService {
    pub async fn sign_in_phone_number(
        &self,
        input: PhoneNumberSignInInput,
    ) -> Result<crate::SignInResult, AuthError> {
        self.validate_phone_number(&input.phone_number).await?;
        let plugin = self.configured_phone_number().ok_or_else(not_enabled)?;
        let user = plugin
            .store
            .find_user_by_phone_number(&input.phone_number)
            .await?;
        let Some(user) = user else {
            let _ = super::super::password::verify_password(input.password, None).await?;
            return Err(PhoneNumberError::InvalidPhoneNumberOrPassword.into());
        };
        if plugin.config.require_verification && !phone_verified(&user) {
            let code = token::generate(&plugin.config);
            token::store_new(self, &plugin.config, &input.phone_number, &code).await?;
            if let Some(sender) = &plugin.config.send_otp {
                sender
                    .send(
                        PhoneNumberMessage {
                            phone_number: input.phone_number,
                            code,
                        },
                        PhoneNumberRequestContext {
                            origin: input.origin,
                            ip_address: input.ip_address,
                            user_agent: input.user_agent,
                        },
                    )
                    .await?;
            }
            return Err(PhoneNumberError::PhoneNumberNotVerified.into());
        }
        let password_hash = self.store.find_password_hash(&user.id).await?;
        if password_hash.is_none() {
            let has_credential_account = self
                .store
                .list_user_accounts(&user.id)
                .await?
                .iter()
                .any(|account| account.provider_id == "credential");
            return Err(if has_credential_account {
                PhoneNumberError::UnexpectedSignIn
            } else {
                PhoneNumberError::InvalidPhoneNumberOrPassword
            }
            .into());
        }
        let valid = super::super::password::verify_password(input.password, password_hash).await?;
        if !valid {
            return Err(PhoneNumberError::InvalidPhoneNumberOrPassword.into());
        }

        self.create_email_password_session(
            user,
            input.remember_me,
            input.ip_address,
            input.user_agent,
        )
        .await
    }

    pub async fn verify_phone_number(
        &self,
        current: Option<&SessionWithUser>,
        input: PhoneNumberVerifyInput,
    ) -> Result<PhoneNumberVerification, AuthError> {
        let plugin = self.configured_phone_number().ok_or_else(not_enabled)?;
        let context = PhoneNumberRequestContext {
            origin: input.origin.clone(),
            ip_address: input.ip_address.clone(),
            user_agent: input.user_agent.clone(),
        };
        token::consume(
            self,
            &plugin.config,
            &input.phone_number,
            &input.code,
            context.clone(),
        )
        .await?;

        let user = self
            .phone_number_user_after_verification(
                current,
                &input.phone_number,
                input.update_phone_number,
                input.additional_fields,
            )
            .await?;

        if let Some(callback) = &plugin.config.callback_on_verification {
            callback
                .call(
                    PhoneNumberVerified {
                        phone_number: input.phone_number,
                        user: user.clone(),
                    },
                    context,
                )
                .await?;
        }

        if input.update_phone_number {
            return Ok(PhoneNumberVerification {
                token: current.map(|session| session.session.token.clone()),
                user,
            });
        }
        if input.disable_session {
            return Ok(PhoneNumberVerification { token: None, user });
        }
        let session = self
            .create_session(
                user,
                AuthenticationMethod::Extension,
                None,
                input.ip_address,
                input.user_agent,
            )
            .await?;
        Ok(PhoneNumberVerification {
            token: Some(session.token),
            user: session.session.user,
        })
    }

    async fn phone_number_user_after_verification(
        &self,
        current: Option<&SessionWithUser>,
        phone_number: &str,
        update_phone_number: bool,
        additional_fields: Map<String, Value>,
    ) -> Result<AuthUser, AuthError> {
        let plugin = self.configured_phone_number().ok_or_else(not_enabled)?;
        if update_phone_number {
            let current = current.ok_or(PhoneNumberError::UserNotFound)?;
            if plugin
                .store
                .find_user_by_phone_number(phone_number)
                .await?
                .is_some()
            {
                return Err(PhoneNumberError::PhoneNumberExists.into());
            }
            return self
                .persist_phone_number(&current.user, Some(phone_number.into()), true)
                .await;
        }
        match plugin.store.find_user_by_phone_number(phone_number).await? {
            Some(user) => {
                self.persist_phone_number(&user, Some(phone_number.into()), true)
                    .await
            }
            None if plugin.config.sign_up_on_verification.is_some() => {
                self.create_phone_number_user(phone_number, additional_fields)
                    .await
            }
            None => Err(PhoneNumberError::FailedToUpdateUser.into()),
        }
    }

    pub async fn request_phone_number_password_reset(
        &self,
        phone_number: &str,
        context: PhoneNumberRequestContext,
    ) -> Result<(), AuthError> {
        let plugin = self.configured_phone_number().ok_or_else(not_enabled)?;
        let user_exists = plugin
            .store
            .find_user_by_phone_number(phone_number)
            .await?
            .is_some();
        let code = token::generate(&plugin.config);
        token::store_new(
            self,
            &plugin.config,
            &token::password_reset_identifier(phone_number),
            &code,
        )
        .await?;
        if user_exists && let Some(sender) = &plugin.config.send_password_reset_otp {
            sender
                .send(
                    PhoneNumberMessage {
                        phone_number: phone_number.into(),
                        code,
                    },
                    context,
                )
                .await?;
        }
        Ok(())
    }

    pub async fn reset_phone_number_password(
        &self,
        phone_number: &str,
        code: &str,
        new_password: String,
    ) -> Result<(), AuthError> {
        let plugin = self.configured_phone_number().ok_or_else(not_enabled)?;
        token::consume_internal(
            self,
            &plugin.config,
            &token::password_reset_identifier(phone_number),
            code,
        )
        .await?;
        let user = plugin
            .store
            .find_user_by_phone_number(phone_number)
            .await?
            .ok_or(PhoneNumberError::UnexpectedError)?;
        self.validate_new_password(&new_password).await?;
        self.set_password_hash_with_database_id(&user.id, self.hash_password(new_password).await?)
            .await?;
        let user = self
            .store
            .update_user_profile(&user.id, UserProfileUpdate::default())
            .await?
            .ok_or(PhoneNumberError::UnexpectedError)?;
        self.after_database_update(&DatabaseRecord::User(user.clone()))
            .await?;
        if let Some(callback) = &self.config.email_and_password.on_password_reset {
            callback.on_password_reset(user.clone()).await?;
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
        Ok(())
    }

    pub(crate) async fn clear_phone_number_for_update(
        &self,
        user: &AuthUser,
    ) -> Result<AuthUser, AuthError> {
        self.persist_phone_number(user, None, false).await
    }

    async fn create_phone_number_user(
        &self,
        phone_number: &str,
        supplied: Map<String, Value>,
    ) -> Result<AuthUser, AuthError> {
        let plugin = self.configured_phone_number().ok_or_else(not_enabled)?;
        let signup = plugin
            .config
            .sign_up_on_verification
            .as_ref()
            .ok_or(PhoneNumberError::FailedToUpdateUser)?;
        let email = signup.temporary_email.generate(phone_number).await?;
        if !super::super::email_password::valid_email(&email) {
            return Err(AuthError::InvalidEmail);
        }
        let name = match &signup.temporary_name {
            Some(generator) => generator.generate(phone_number).await?,
            None => phone_number.into(),
        };
        let additional_fields = without_phone_fields(supplied);
        let internal_fields = Map::from_iter([
            (PHONE_NUMBER.into(), json!(phone_number)),
            (PHONE_NUMBER_VERIFIED.into(), json!(true)),
        ]);
        let now = Utc::now();
        let user = self
            .prepare_user_create_with_internal_fields(
                AuthUser {
                    id: String::new(),
                    username: None,
                    display_username: None,
                    name,
                    email: email.to_lowercase(),
                    email_verified: false,
                    image: None,
                    additional_fields,
                    role: self.default_user_role(),
                    is_anonymous: false,
                    banned: false,
                    ban_reason: None,
                    ban_expires: None,
                    created_at: now,
                    updated_at: now,
                },
                internal_fields,
            )
            .await?;
        let user = match plugin.store.create_phone_number_user(user).await? {
            PhoneNumberWriteOutcome::Written(user) => user,
            PhoneNumberWriteOutcome::AlreadyExists => {
                return Err(PhoneNumberError::PhoneNumberExists.into());
            }
            PhoneNumberWriteOutcome::NotFound => {
                return Err(PhoneNumberError::FailedToUpdateUser.into());
            }
        };
        self.finish_user_create(&user).await?;
        Ok(user)
    }

    async fn persist_phone_number(
        &self,
        original: &AuthUser,
        phone_number: Option<String>,
        verified: bool,
    ) -> Result<AuthUser, AuthError> {
        let plugin = self.configured_phone_number().ok_or_else(not_enabled)?;
        let mut candidate = original.clone();
        match &phone_number {
            Some(phone_number) => {
                candidate
                    .additional_fields
                    .insert(PHONE_NUMBER.into(), json!(phone_number));
            }
            None => {
                candidate
                    .additional_fields
                    .insert(PHONE_NUMBER.into(), Value::Null);
            }
        }
        candidate
            .additional_fields
            .insert(PHONE_NUMBER_VERIFIED.into(), json!(verified));
        candidate.updated_at = Utc::now();
        let candidate = self.prepare_user_update(original, candidate).await?;
        let phone_number = candidate
            .additional_fields
            .get(PHONE_NUMBER)
            .and_then(Value::as_str)
            .map(str::to_owned);
        let verified = candidate
            .additional_fields
            .get(PHONE_NUMBER_VERIFIED)
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let user = match plugin
            .store
            .update_user_phone_number(&original.id, phone_number, verified)
            .await?
        {
            PhoneNumberWriteOutcome::Written(user) => user,
            PhoneNumberWriteOutcome::AlreadyExists => {
                return Err(PhoneNumberError::PhoneNumberExists.into());
            }
            PhoneNumberWriteOutcome::NotFound => return Err(PhoneNumberError::UserNotFound.into()),
        };
        self.after_database_update(&DatabaseRecord::User(user.clone()))
            .await?;
        Ok(user)
    }
}

fn phone_verified(user: &AuthUser) -> bool {
    user.additional_fields
        .get(PHONE_NUMBER_VERIFIED)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn without_phone_fields(mut fields: Map<String, Value>) -> Map<String, Value> {
    fields.remove(PHONE_NUMBER);
    fields.remove(PHONE_NUMBER_VERIFIED);
    fields
}

fn not_enabled() -> AuthError {
    AuthError::InvalidConfiguration("the phone-number plugin is not enabled".into())
}
