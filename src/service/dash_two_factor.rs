use super::AuthService;
use crate::{AuthError, DatabaseIdInput, TwoFactorRecord};
use rand::RngExt;

pub(crate) struct DashTwoFactorSetup {
    pub secret: String,
    pub totp_uri: String,
    pub backup_codes: Vec<String>,
}

impl AuthService {
    pub(crate) async fn dash_enable_two_factor(
        &self,
        user_id: &str,
        account: &str,
    ) -> Result<DashTwoFactorSetup, AuthError> {
        let plugin = self.two_factor_plugin()?;
        plugin.store.delete_two_factor(user_id).await?;
        let secret = random_alphanumeric(32);
        let backup_codes = backup_codes(
            plugin.config.backup_codes.amount,
            plugin.config.backup_codes.length,
        );
        let encrypted_secret =
            crate::two_factor::crypto::encrypt(&self.config.secret, secret.as_bytes())?;
        let encoded_codes = serde_json::to_vec(&backup_codes)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        let encrypted_backup_codes =
            crate::two_factor::crypto::encrypt(&self.config.secret, &encoded_codes)?;
        let id = self.database_id_plan("twoFactor", DatabaseIdInput::Absent, false);
        let prepare_id = || id.prepare(self.store.as_ref());
        plugin
            .store
            .upsert_two_factor(
                &prepare_id,
                TwoFactorRecord {
                    id: String::new(),
                    user_id: user_id.to_owned(),
                    encrypted_secret,
                    encrypted_backup_codes,
                    verified: true,
                    failed_verification_count: 0,
                    locked_until: None,
                },
            )
            .await?;
        plugin.store.set_two_factor_enabled(user_id, true).await?;
        let issuer = plugin
            .config
            .issuer
            .clone()
            .unwrap_or_else(|| "Better Auth".into());
        let totp_uri = crate::two_factor::crypto::totp_uri(
            &secret,
            &issuer,
            account,
            plugin.config.totp.digits,
            plugin.config.totp.period.num_seconds(),
        );
        Ok(DashTwoFactorSetup {
            secret,
            totp_uri,
            backup_codes,
        })
    }

    pub(crate) async fn dash_two_factor_totp_uri(
        &self,
        user_id: &str,
        account: &str,
    ) -> Result<Option<String>, AuthError> {
        let plugin = self.two_factor_plugin()?;
        let Some(record) = plugin.store.find_two_factor(user_id).await? else {
            return Ok(None);
        };
        let secret = crate::two_factor::crypto::decrypt(
            &self.config.secret,
            &record.encrypted_secret,
        )
        .ok()
        .and_then(|secret| String::from_utf8(secret).ok())
        .unwrap_or(record.encrypted_secret);
        let issuer = plugin
            .config
            .issuer
            .clone()
            .unwrap_or_else(|| "Better Auth".into());
        Ok(Some(crate::two_factor::crypto::totp_uri(
            &secret,
            &issuer,
            account,
            plugin.config.totp.digits,
            plugin.config.totp.period.num_seconds(),
        )))
    }

    pub(crate) async fn dash_generate_backup_codes(
        &self,
        user_id: &str,
    ) -> Result<Option<Vec<String>>, AuthError> {
        let plugin = self.two_factor_plugin()?;
        let Some(record) = plugin.store.find_two_factor(user_id).await? else {
            return Ok(None);
        };
        let codes = backup_codes(
            plugin.config.backup_codes.amount,
            plugin.config.backup_codes.length,
        );
        let encoded = serde_json::to_vec(&codes)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        let encrypted = crate::two_factor::crypto::encrypt(&self.config.secret, &encoded)?;
        if !plugin
            .store
            .replace_backup_codes(user_id, &record.encrypted_backup_codes, encrypted)
            .await?
        {
            return Err(AuthError::Storage(
                "two-factor backup codes changed concurrently".into(),
            ));
        }
        Ok(Some(codes))
    }
}

fn backup_codes(amount: usize, length: usize) -> Vec<String> {
    (0..amount)
        .map(|_| {
            let raw = random_alphanumeric(length);
            let split = raw.len().min(5);
            format!("{}-{}", &raw[..split], &raw[split..])
        })
        .collect()
}

fn random_alphanumeric(length: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}
