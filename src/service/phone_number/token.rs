use super::AuthService;
use crate::{
    AuthError, PhoneNumberConfig, PhoneNumberError, PhoneNumberRequestContext, VerificationValue,
};
use chrono::Utc;
use rand::RngExt;

struct OtpRecord {
    code: String,
    attempts: u32,
}

pub(super) fn password_reset_identifier(phone_number: &str) -> String {
    format!("{phone_number}-request-password-reset")
}

pub(super) fn generate(config: &PhoneNumberConfig) -> String {
    let mut rng = rand::rng();
    (0..config.otp_length)
        .map(|_| char::from(b'0' + rng.random_range(0..10)))
        .collect()
}

pub(super) async fn store_new(
    service: &AuthService,
    config: &PhoneNumberConfig,
    identifier: &str,
    code: &str,
) -> Result<(), AuthError> {
    let now = Utc::now();
    let value = VerificationValue::new(identifier, format!("{code}:0"), now + config.expires_in);
    if service
        .create_verification_value(value.clone())
        .await
        .is_err()
    {
        service.delete_verification_value(identifier).await?;
        service.create_verification_value(value).await?;
    }
    Ok(())
}

pub(super) async fn consume(
    service: &AuthService,
    config: &PhoneNumberConfig,
    identifier: &str,
    provided: &str,
    context: PhoneNumberRequestContext,
) -> Result<(), AuthError> {
    if let Some(verifier) = &config.verify_otp {
        if !verifier.verify(identifier, provided, context).await? {
            return Err(PhoneNumberError::InvalidOtp.into());
        }
        service.delete_verification_value(identifier).await?;
        return Ok(());
    }

    consume_internal(service, config, identifier, provided).await
}

pub(super) async fn consume_internal(
    service: &AuthService,
    config: &PhoneNumberConfig,
    identifier: &str,
    provided: &str,
) -> Result<(), AuthError> {
    let Some(existing) = service.find_verification_value(identifier).await? else {
        return Err(PhoneNumberError::OtpNotFound.into());
    };
    if existing.expires_at < Utc::now() {
        service.delete_verification_value(identifier).await?;
        return Err(PhoneNumberError::OtpExpired.into());
    }
    let existing_record = record(&existing)?;
    if existing_record.attempts >= config.allowed_attempts {
        service.delete_verification_value(identifier).await?;
        return Err(PhoneNumberError::TooManyAttempts.into());
    }

    let Some(value) = service
        .consume_verification_value(identifier, Utc::now())
        .await?
    else {
        return Err(PhoneNumberError::InvalidOtp.into());
    };
    let mut record = record(&value)?;
    if record.code == provided {
        return Ok(());
    }
    record.attempts += 1;
    service
        .create_verification_value(VerificationValue::new(
            identifier,
            format!("{}:{}", record.code, record.attempts),
            value.expires_at,
        ))
        .await?;
    Err(PhoneNumberError::InvalidOtp.into())
}

fn record(value: &VerificationValue) -> Result<OtpRecord, AuthError> {
    let (code, attempts) = value
        .value
        .split_once(':')
        .unwrap_or((value.value.as_str(), "0"));
    let attempts = attempts.parse().unwrap_or_default();
    Ok(OtpRecord {
        code: code.into(),
        attempts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_identifier_matches_better_auth() {
        assert_eq!(
            password_reset_identifier("+15551234567"),
            "+15551234567-request-password-reset"
        );
    }
}
