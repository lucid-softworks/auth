use super::{AuthService, BackupCodeVerification, TwoFactorError, TwoFactorVerification};
use crate::{AuthError, SessionWithUser, TwoFactorOtp, VerificationValue};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngExt;
use sha2::{Digest, Sha256};

const OTP_PREFIX: &str = "2fa-otp-";

impl AuthService {
    pub(crate) async fn verify_two_factor_totp(
        &self,
        active: Option<(SessionWithUser, String)>,
        challenge_identifier: Option<String>,
        code: &str,
        trust_device: bool,
    ) -> Result<TwoFactorVerification, AuthError> {
        let plugin = self.two_factor_plugin()?;
        if plugin.config.totp.disabled {
            return Err(TwoFactorError::TotpNotConfigured.into());
        }
        let context = self
            .verification_context(active, challenge_identifier)
            .await?;
        let record = plugin
            .store
            .find_two_factor(context.user.id)
            .await?
            .ok_or(TwoFactorError::TotpNotEnabled)?;
        if context.is_sign_in() && !record.verified {
            return Err(TwoFactorError::TotpNotEnabled.into());
        }
        if context.is_sign_in() {
            self.assert_two_factor_unlocked(&record).await?;
            self.check_challenge_attempts(&context, 5).await?;
        }
        let encrypted = record.encrypted_secret.as_str();
        let secret = String::from_utf8(crate::two_factor::crypto::decrypt(
            &self.config.secret,
            encrypted,
        )?)
        .map_err(|_| AuthError::Storage("TOTP secret is invalid".into()))?;
        let counter = crate::two_factor::crypto::verify_totp(
            &secret,
            code,
            plugin.config.totp.digits,
            plugin.config.totp.period.num_seconds(),
            Utc::now().timestamp(),
        );
        let Some(_) = counter else {
            if context.is_sign_in() {
                self.record_challenge_failure(&context).await?;
            }
            return Err(TwoFactorError::InvalidCode.into());
        };
        let completing_enrollment =
            !record.verified || !plugin.store.two_factor_enabled(context.user.id).await?;
        if completing_enrollment
            && !plugin
                .store
                .complete_two_factor_enrollment(context.user.id)
                .await?
        {
            return Err(TwoFactorError::TotpNotEnabled.into());
        }
        if completing_enrollment && let Some((session, token)) = context.active.as_ref() {
            self.reset_two_factor_failures(context.user.id).await?;
            let result = self.rotate_active_session(session, token).await?;
            let trust_cookie = if trust_device {
                Some(self.create_trust_device(context.user.id).await?)
            } else {
                None
            };
            return Ok(TwoFactorVerification {
                result,
                remember_me: Some(true),
                trust_cookie,
            });
        }
        self.complete_two_factor(context, trust_device).await
    }

    pub(crate) async fn send_two_factor_otp(
        &self,
        active: Option<(SessionWithUser, String)>,
        challenge_identifier: Option<String>,
    ) -> Result<(), AuthError> {
        let plugin = self.two_factor_plugin()?;
        let otp = plugin
            .config
            .otp
            .as_ref()
            .ok_or(TwoFactorError::OtpNotConfigured)?;
        let context = self
            .verification_context(active, challenge_identifier)
            .await?;
        let code = random_digits(otp.digits);
        let key = context.key();
        let identifier = otp_identifier(&key);
        let now = Utc::now();
        let _ = self.consume_verification_record(&identifier, now).await?;
        self.create_verification_record(VerificationValue::new(
            identifier,
            format!("{}:0", otp_hash(&code)),
            now + otp.period,
        ))
        .await?;
        let _ = otp
            .sender
            .send(TwoFactorOtp {
                user: context.user,
                code,
            })
            .await;
        Ok(())
    }

    pub(crate) async fn verify_two_factor_otp(
        &self,
        active: Option<(SessionWithUser, String)>,
        challenge_identifier: Option<String>,
        code: &str,
        trust_device: bool,
    ) -> Result<TwoFactorVerification, AuthError> {
        let plugin = self.two_factor_plugin()?;
        let otp = plugin
            .config
            .otp
            .as_ref()
            .ok_or(TwoFactorError::OtpNotConfigured)?;
        let context = self
            .verification_context(active, challenge_identifier)
            .await?;
        let existing = plugin.store.find_two_factor(context.user.id).await?;
        if context.is_sign_in() {
            if !plugin.store.two_factor_enabled(context.user.id).await? {
                return Err(TwoFactorError::OtpNotEnabled.into());
            }
            if let Some(record) = existing.as_ref() {
                self.assert_two_factor_unlocked(record).await?;
            }
        }
        let key = context.key();
        let identifier = otp_identifier(&key);
        let value = self
            .consume_verification_record(&identifier, Utc::now())
            .await?
            .ok_or(TwoFactorError::OtpExpired)?;
        let (expected, attempts) = otp_value(&value.value, otp.allowed_attempts);
        if attempts >= otp.allowed_attempts {
            return Err(TwoFactorError::TooManyAttempts.into());
        }
        if !constant_time_equal(expected.as_bytes(), otp_hash(code).as_bytes()) {
            self.create_verification_record(VerificationValue::new(
                identifier,
                format!("{expected}:{}", attempts + 1),
                value.expires_at,
            ))
            .await?;
            if context.is_sign_in() {
                self.record_two_factor_failure(context.user.id).await?;
            }
            return Err(TwoFactorError::InvalidCode.into());
        }
        if !plugin.store.two_factor_enabled(context.user.id).await? {
            plugin
                .store
                .set_two_factor_enabled(context.user.id, true)
                .await?;
            if let Some((session, token)) = context.active.as_ref() {
                let result = self.rotate_active_session(session, token).await?;
                return Ok(TwoFactorVerification {
                    result,
                    remember_me: Some(true),
                    trust_cookie: None,
                });
            }
        }
        self.complete_two_factor(context, trust_device).await
    }

    pub(crate) async fn verify_two_factor_backup_code(
        &self,
        active: Option<(SessionWithUser, String)>,
        challenge_identifier: Option<String>,
        code: &str,
        disable_session: bool,
        trust_device: bool,
    ) -> Result<BackupCodeVerification, AuthError> {
        let context = self
            .verification_context(active, challenge_identifier)
            .await?;
        let plugin = self.two_factor_plugin()?;
        let record = plugin
            .store
            .find_two_factor(context.user.id)
            .await?
            .ok_or(TwoFactorError::BackupCodesNotEnabled)?;
        if context.is_sign_in() {
            self.assert_two_factor_unlocked(&record).await?;
            self.check_challenge_attempts(&context, 5).await?;
        }
        let encrypted = record.encrypted_backup_codes.as_str();
        let mut codes: Vec<String> = serde_json::from_slice(&crate::two_factor::crypto::decrypt(
            &self.config.secret,
            encrypted,
        )?)
        .map_err(|error| AuthError::Storage(error.to_string()))?;
        let Some(index) = codes
            .iter()
            .position(|candidate| constant_time_equal(candidate.as_bytes(), code.as_bytes()))
        else {
            if context.is_sign_in() {
                self.record_challenge_failure(&context).await?;
            }
            return Err(TwoFactorError::InvalidBackupCode.into());
        };
        codes.remove(index);
        let encoded =
            serde_json::to_vec(&codes).map_err(|error| AuthError::Storage(error.to_string()))?;
        let replacement = crate::two_factor::crypto::encrypt(&self.config.secret, &encoded)?;
        if !plugin
            .store
            .replace_backup_codes(context.user.id, encrypted, replacement)
            .await?
        {
            return Err(TwoFactorError::BackupCodeConflict.into());
        }
        if disable_session {
            let token = context.active.as_ref().map(|(_, token)| token.clone());
            return Ok(BackupCodeVerification {
                completed: None,
                user: context.user,
                token,
            });
        }
        let user = context.user.clone();
        let completed = self.complete_two_factor(context, trust_device).await?;
        Ok(BackupCodeVerification {
            completed: Some(completed),
            user,
            token: None,
        })
    }
}

fn otp_identifier(key: &str) -> String {
    format!("{OTP_PREFIX}{key}")
}

fn otp_value(value: &str, invalid_attempts: u32) -> (&str, u32) {
    value
        .rsplit_once(':')
        .map_or((value, 0), |(otp, attempts)| {
            (otp, attempts.parse().unwrap_or(invalid_attempts))
        })
}

fn otp_hash(code: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))
}

fn random_digits(length: usize) -> String {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| char::from(b'0' + rng.random_range(0..10)))
        .collect()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}
