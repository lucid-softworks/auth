mod account;
mod token;

use super::AuthService;
use crate::{
    AuthError, PhoneNumberConfig, PhoneNumberError, PhoneNumberMessage, PhoneNumberPlugin,
    PhoneNumberRequestContext,
};

impl AuthService {
    pub async fn send_phone_number_otp(
        &self,
        phone_number: &str,
        context: PhoneNumberRequestContext,
    ) -> Result<(), AuthError> {
        let config = self.phone_number_config()?;
        let sender = config
            .send_otp
            .as_ref()
            .ok_or(PhoneNumberError::SendOtpNotImplemented)?;
        self.validate_phone_number(phone_number).await?;
        let code = token::generate(config);
        token::store_new(self, config, phone_number, &code).await?;
        sender
            .send(
                PhoneNumberMessage {
                    phone_number: phone_number.into(),
                    code,
                },
                context,
            )
            .await
    }

    /// Native equivalent of Better Auth's server-only `consumePhoneNumberOTP` API.
    pub async fn consume_phone_number_otp(
        &self,
        phone_number: &str,
        code: &str,
    ) -> Result<(), AuthError> {
        token::consume(
            self,
            self.phone_number_config()?,
            phone_number,
            code,
            PhoneNumberRequestContext::default(),
        )
        .await
    }

    pub(crate) fn configured_phone_number(&self) -> Option<&PhoneNumberPlugin> {
        self.plugins.find::<PhoneNumberPlugin>()
    }

    pub(crate) fn phone_number_config(&self) -> Result<&PhoneNumberConfig, AuthError> {
        self.configured_phone_number()
            .map(|plugin| plugin.config.as_ref())
            .ok_or_else(|| {
                AuthError::InvalidConfiguration("the phone-number plugin is not enabled".into())
            })
    }

    pub(super) async fn validate_phone_number(&self, phone_number: &str) -> Result<(), AuthError> {
        if let Some(validator) = &self.phone_number_config()?.validator
            && !validator.validate(phone_number).await?
        {
            return Err(PhoneNumberError::InvalidPhoneNumber.into());
        }
        Ok(())
    }
}
