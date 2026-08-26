use super::AuthService;
#[cfg(feature = "axum")]
use super::TwoFactorEnableResult;
use crate::{AuthError, TwoFactorError};
#[cfg(feature = "axum")]
use crate::{SessionWithUser, TwoFactorRecord};
#[cfg(feature = "axum")]
use rand::RngExt;

impl AuthService {
    #[cfg(feature = "axum")]
    pub(crate) async fn enable_two_factor_totp(
        &self,
        session: &SessionWithUser,
        token: &str,
        password: Option<String>,
        issuer: Option<String>,
    ) -> Result<TwoFactorEnableResult, AuthError> {
        self.require_two_factor_password(&session.user.id, password)
            .await?;
        let plugin = self.two_factor_plugin()?;
        if plugin.config.totp.disabled {
            return Err(TwoFactorError::TotpNotConfigured.into());
        }
        let secret = random_alphanumeric(32);
        let backup_codes = generate_backup_codes(
            plugin.config.backup_codes.amount,
            plugin.config.backup_codes.length,
        );
        let encrypted_secret =
            crate::two_factor::crypto::encrypt(&self.config.secret, secret.as_bytes())?;
        let encoded_codes = serde_json::to_vec(&backup_codes)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        let encrypted_backup_codes =
            crate::two_factor::crypto::encrypt(&self.config.secret, &encoded_codes)?;
        let existing = plugin.store.find_two_factor(&session.user.id).await?;
        let already_verified = existing.as_ref().is_some_and(|record| record.verified);
        let verified = already_verified || plugin.config.skip_verification_on_enable;
        plugin
            .store
            .upsert_two_factor(TwoFactorRecord {
                id: existing
                    .as_ref()
                    .map_or_else(uuid::Uuid::new_v4, |record| record.id),
                user_id: session.user.id.clone(),
                encrypted_secret,
                encrypted_backup_codes,
                verified,
                failed_verification_count: 0,
                locked_until: None,
            })
            .await?;
        if verified {
            plugin
                .store
                .set_two_factor_enabled(&session.user.id, true)
                .await?;
        }
        let replacement_session = if verified {
            Some(self.rotate_active_session(session, token).await?)
        } else {
            None
        };
        let issuer = issuer
            .or_else(|| plugin.config.issuer.clone())
            .unwrap_or_else(|| "Better Auth".into());
        let totp_uri = crate::two_factor::crypto::totp_uri(
            &secret,
            &issuer,
            &session.user.email,
            plugin.config.totp.digits,
            plugin.config.totp.period.num_seconds(),
        );
        Ok(TwoFactorEnableResult {
            method: "totp",
            totp_uri: Some(totp_uri),
            backup_codes: Some(backup_codes),
            replacement_session,
        })
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn enable_two_factor_otp(
        &self,
        session: &SessionWithUser,
        token: &str,
        password: Option<String>,
    ) -> Result<TwoFactorEnableResult, AuthError> {
        self.require_two_factor_password(&session.user.id, password)
            .await?;
        let plugin = self.two_factor_plugin()?;
        if plugin.config.otp.is_none() {
            return Err(TwoFactorError::OtpNotConfigured.into());
        }
        plugin
            .store
            .set_two_factor_enabled(&session.user.id, true)
            .await?;
        let replacement = self.rotate_active_session(session, token).await?;
        Ok(TwoFactorEnableResult {
            method: "otp",
            totp_uri: None,
            backup_codes: None,
            replacement_session: Some(replacement),
        })
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn disable_two_factor(
        &self,
        session: &SessionWithUser,
        token: &str,
        password: Option<String>,
        trust_cookie: Option<&str>,
    ) -> Result<super::SignInResult, AuthError> {
        if self.config.session_fresh_age != chrono::Duration::zero()
            && session.session.created_at + self.config.session_fresh_age <= chrono::Utc::now()
        {
            return Err(AuthError::SessionNotFresh);
        }
        self.require_two_factor_password(&session.user.id, password)
            .await?;
        self.two_factor_plugin()?
            .store
            .delete_two_factor(&session.user.id)
            .await?;
        self.revoke_trust_device(trust_cookie).await?;
        self.rotate_active_session(session, token).await
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn get_two_factor_totp_uri(
        &self,
        session: &SessionWithUser,
        password: Option<String>,
    ) -> Result<String, AuthError> {
        let plugin = self.two_factor_plugin()?;
        if plugin.config.totp.disabled {
            return Err(TwoFactorError::TotpNotConfigured.into());
        }
        let record = plugin
            .store
            .find_two_factor(&session.user.id)
            .await?
            .ok_or(TwoFactorError::TotpNotEnabled)?;
        let encrypted = record.encrypted_secret;
        self.require_two_factor_password(&session.user.id, password)
            .await?;
        let secret = String::from_utf8(crate::two_factor::crypto::decrypt(
            &self.config.secret,
            &encrypted,
        )?)
        .map_err(|_| AuthError::Storage("TOTP secret is invalid".into()))?;
        let issuer = plugin
            .config
            .issuer
            .clone()
            .unwrap_or_else(|| "Better Auth".into());
        Ok(crate::two_factor::crypto::totp_uri(
            &secret,
            &issuer,
            &session.user.email,
            plugin.config.totp.digits,
            plugin.config.totp.period.num_seconds(),
        ))
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn generate_two_factor_backup_codes(
        &self,
        session: &SessionWithUser,
        password: Option<String>,
    ) -> Result<Vec<String>, AuthError> {
        self.require_two_factor_password(&session.user.id, password)
            .await?;
        let plugin = self.two_factor_plugin()?;
        let mut record = plugin
            .store
            .find_two_factor(&session.user.id)
            .await?
            .ok_or(TwoFactorError::NotEnabled)?;
        if !plugin.store.two_factor_enabled(&session.user.id).await? {
            return Err(TwoFactorError::NotEnabled.into());
        }
        let codes = generate_backup_codes(
            plugin.config.backup_codes.amount,
            plugin.config.backup_codes.length,
        );
        let encoded =
            serde_json::to_vec(&codes).map_err(|error| AuthError::Storage(error.to_string()))?;
        record.encrypted_backup_codes =
            crate::two_factor::crypto::encrypt(&self.config.secret, &encoded)?;
        plugin.store.upsert_two_factor(record).await?;
        Ok(codes)
    }

    pub async fn view_two_factor_backup_codes(
        &self,
        user_id: &str,
    ) -> Result<Vec<String>, AuthError> {
        let record = self
            .two_factor_plugin()?
            .store
            .find_two_factor(user_id)
            .await?
            .ok_or(TwoFactorError::BackupCodesNotEnabled)?;
        let encrypted = record.encrypted_backup_codes;
        serde_json::from_slice(&crate::two_factor::crypto::decrypt(
            &self.config.secret,
            &encrypted,
        )?)
        .map_err(|error| AuthError::Storage(error.to_string()))
    }

    /// Server-only equivalent of Better Auth's `generateTOTP` endpoint.
    pub fn generate_two_factor_totp(&self, secret: &str) -> Result<String, AuthError> {
        let config = &self.two_factor_plugin()?.config.totp;
        if config.disabled {
            return Err(TwoFactorError::TotpNotConfigured.into());
        }
        Ok(crate::two_factor::crypto::current_totp(
            secret,
            config.digits,
            config.period.num_seconds(),
            chrono::Utc::now().timestamp(),
        ))
    }
}

#[cfg(feature = "axum")]
pub(super) fn generate_backup_codes(amount: usize, length: usize) -> Vec<String> {
    (0..amount)
        .map(|_| {
            let raw = random_alphanumeric(length);
            let split = raw.len().min(5);
            format!("{}-{}", &raw[..split], &raw[split..])
        })
        .collect()
}

#[cfg(feature = "axum")]
fn random_alphanumeric(length: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}
