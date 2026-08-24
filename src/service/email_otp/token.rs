use super::AuthService;
use crate::{
    AuthError, EmailOtpConfig, EmailOtpError, EmailOtpResendStrategy, EmailOtpStorage,
    EmailOtpType, VerificationValue,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

pub(super) const PURPOSE: &str = "email-otp";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OtpRecord {
    otp: String,
    attempts: u32,
}

pub(super) fn identifier(kind: EmailOtpType, email: &str) -> String {
    format!("{}-otp-{email}", kind.as_str())
}

pub(super) async fn generate(
    config: &EmailOtpConfig,
    email: &str,
    kind: EmailOtpType,
) -> Result<String, AuthError> {
    let otp = match &config.generator {
        Some(generator) => generator.generate(email, kind).await?,
        None => {
            let mut rng = rand::rng();
            (0..config.otp_length)
                .map(|_| char::from(b'0' + rng.random_range(0..10)))
                .collect()
        }
    };
    if otp.is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "email-OTP generators must return a non-empty value".into(),
        ));
    }
    Ok(otp)
}

pub(super) async fn resolve(
    service: &AuthService,
    config: &EmailOtpConfig,
    identifier: &str,
    email: &str,
    kind: EmailOtpType,
) -> Result<String, AuthError> {
    if config.resend_strategy == EmailOtpResendStrategy::Reuse
        && let Some(otp) = reusable(service, config, identifier).await?
    {
        return Ok(otp);
    }
    let otp = generate(config, email, kind).await?;
    store_new(service, config, identifier, &otp).await?;
    Ok(otp)
}

pub(super) async fn store_new(
    service: &AuthService,
    config: &EmailOtpConfig,
    identifier: &str,
    otp: &str,
) -> Result<(), AuthError> {
    let stored = store_otp(service, config, otp).await?;
    let now = Utc::now();
    let value = VerificationValue {
        purpose: PURPOSE.into(),
        identifier: identifier.into(),
        payload: json!(OtpRecord {
            otp: stored,
            attempts: 0,
        }),
        additional_fields: serde_json::Map::new(),
        expires_at: now + config.expires_in,
        created_at: now,
    };
    if service
        .create_verification_value(value.clone())
        .await
        .is_err()
    {
        service
            .delete_verification_value(PURPOSE, identifier)
            .await?;
        service.create_verification_value(value).await?;
    }
    Ok(())
}

pub(super) async fn retrieve(
    service: &AuthService,
    config: &EmailOtpConfig,
    identifier: &str,
) -> Result<Option<String>, AuthError> {
    let Some(value) = service.find_verification_value(PURPOSE, identifier).await? else {
        return Ok(None);
    };
    if value.expires_at <= Utc::now() {
        return Ok(None);
    }
    let record = record(&value)?;
    recover_otp(service, config, &record.otp).await.map(Some)
}

pub(super) async fn check(
    service: &AuthService,
    config: &EmailOtpConfig,
    identifier: &str,
    provided: &str,
) -> Result<(), AuthError> {
    let Some(mut value) = service.find_verification_value(PURPOSE, identifier).await? else {
        return Err(EmailOtpError::InvalidOtp.into());
    };
    if value.expires_at <= Utc::now() {
        service
            .delete_verification_value(PURPOSE, identifier)
            .await?;
        return Err(EmailOtpError::OtpExpired.into());
    }
    let mut record = record(&value)?;
    if record.attempts >= config.allowed_attempts {
        service
            .delete_verification_value(PURPOSE, identifier)
            .await?;
        return Err(EmailOtpError::TooManyAttempts.into());
    }
    if verify_otp(service, config, &record.otp, provided).await? {
        return Ok(());
    }
    record.attempts += 1;
    value.payload = json!(record);
    value.identifier = identifier.into();
    service.update_verification_value(value).await?;
    Err(EmailOtpError::InvalidOtp.into())
}

pub(super) async fn consume(
    service: &AuthService,
    config: &EmailOtpConfig,
    identifier: &str,
    provided: &str,
) -> Result<(), AuthError> {
    let existing = service.find_verification_value(PURPOSE, identifier).await?;
    if existing
        .as_ref()
        .is_some_and(|value| value.expires_at <= Utc::now())
    {
        service
            .delete_verification_value(PURPOSE, identifier)
            .await?;
        return Err(EmailOtpError::OtpExpired.into());
    }
    let Some(value) = service
        .consume_verification_value(PURPOSE, identifier, Utc::now())
        .await?
    else {
        return Err(EmailOtpError::InvalidOtp.into());
    };
    let mut record = record(&value)?;
    if record.attempts >= config.allowed_attempts {
        return Err(EmailOtpError::TooManyAttempts.into());
    }
    if verify_otp(service, config, &record.otp, provided).await? {
        return Ok(());
    }
    record.attempts += 1;
    service
        .create_verification_value(VerificationValue {
            purpose: PURPOSE.into(),
            identifier: identifier.into(),
            payload: json!(record),
            additional_fields: value.additional_fields,
            expires_at: value.expires_at,
            created_at: value.created_at,
        })
        .await?;
    Err(EmailOtpError::InvalidOtp.into())
}

async fn reusable(
    service: &AuthService,
    config: &EmailOtpConfig,
    identifier: &str,
) -> Result<Option<String>, AuthError> {
    let Some(mut value) = service.find_verification_value(PURPOSE, identifier).await? else {
        return Ok(None);
    };
    if value.expires_at <= Utc::now() {
        return Ok(None);
    }
    let record = record(&value)?;
    if record.attempts >= config.allowed_attempts {
        return Ok(None);
    }
    let otp = match recover_otp(service, config, &record.otp).await {
        Ok(otp) => otp,
        Err(AuthError::EmailOtp(EmailOtpError::HashedOtpUnavailable)) => return Ok(None),
        Err(error) => return Err(error),
    };
    value.expires_at = Utc::now() + config.expires_in;
    value.identifier = identifier.into();
    service.update_verification_value(value).await?;
    Ok(Some(otp))
}

fn record(value: &VerificationValue) -> Result<OtpRecord, AuthError> {
    serde_json::from_value(value.payload.clone())
        .map_err(|_| AuthError::Storage("email-OTP verification payload is invalid".into()))
}

async fn store_otp(
    service: &AuthService,
    config: &EmailOtpConfig,
    otp: &str,
) -> Result<String, AuthError> {
    match &config.storage {
        EmailOtpStorage::Plain => Ok(otp.into()),
        EmailOtpStorage::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(otp.as_bytes()))),
        EmailOtpStorage::Encrypted => {
            crate::two_factor::crypto::encrypt(&service.config.secret, otp.as_bytes())
        }
        EmailOtpStorage::CustomHash(hasher) => hasher.hash(otp).await,
        EmailOtpStorage::CustomEncryption(encryptor) => encryptor.encrypt(otp).await,
    }
}

async fn recover_otp(
    service: &AuthService,
    config: &EmailOtpConfig,
    stored: &str,
) -> Result<String, AuthError> {
    match &config.storage {
        EmailOtpStorage::Plain => Ok(stored.into()),
        EmailOtpStorage::Hashed | EmailOtpStorage::CustomHash(_) => {
            Err(EmailOtpError::HashedOtpUnavailable.into())
        }
        EmailOtpStorage::Encrypted => String::from_utf8(crate::two_factor::crypto::decrypt(
            &service.config.secret,
            stored,
        )?)
        .map_err(|_| AuthError::Storage("email-OTP ciphertext is not UTF-8".into())),
        EmailOtpStorage::CustomEncryption(encryptor) => encryptor.decrypt(stored).await,
    }
}

async fn verify_otp(
    service: &AuthService,
    config: &EmailOtpConfig,
    stored: &str,
    provided: &str,
) -> Result<bool, AuthError> {
    let candidate = match &config.storage {
        EmailOtpStorage::Plain => provided.into(),
        EmailOtpStorage::Hashed => URL_SAFE_NO_PAD.encode(Sha256::digest(provided.as_bytes())),
        EmailOtpStorage::Encrypted => recover_otp(service, config, stored).await?,
        EmailOtpStorage::CustomHash(hasher) => hasher.hash(provided).await?,
        EmailOtpStorage::CustomEncryption(encryptor) => encryptor.decrypt(stored).await?,
    };
    let expected = if matches!(
        config.storage,
        EmailOtpStorage::Encrypted | EmailOtpStorage::CustomEncryption(_)
    ) {
        provided
    } else {
        stored
    };
    constant_time_equal(&service.config.secret, expected, &candidate)
}

fn constant_time_equal(secret: &[u8], left: &str, right: &str) -> Result<bool, AuthError> {
    type HmacSha256 = Hmac<Sha256>;
    let mut left_mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| AuthError::InvalidConfiguration("email-OTP key is invalid".into()))?;
    left_mac.update(left.as_bytes());
    let tag = left_mac.finalize().into_bytes();
    let mut right_mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| AuthError::InvalidConfiguration("email-OTP key is invalid".into()))?;
    right_mac.update(right.as_bytes());
    Ok(right_mac.verify_slice(&tag).is_ok())
}
