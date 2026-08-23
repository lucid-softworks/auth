#[cfg(feature = "axum")]
mod challenge;
mod enrollment;
#[cfg(feature = "axum")]
mod verification;

use super::AuthService;
#[cfg(feature = "axum")]
use super::{SignInResult, password::verify_password};
use crate::{AuthError, TwoFactorPlugin};
#[cfg(feature = "axum")]
use crate::{AuthUser, SessionWithUser, TwoFactorError, TwoFactorRecord};
#[cfg(feature = "axum")]
use chrono::{DateTime, Utc};
#[cfg(feature = "axum")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "axum")]
pub(crate) struct TwoFactorEnableResult {
    pub method: &'static str,
    pub totp_uri: Option<String>,
    pub backup_codes: Option<Vec<String>>,
    pub replacement_session: Option<SignInResult>,
}

#[cfg(feature = "axum")]
pub(crate) enum TwoFactorSignInOutcome {
    Continue {
        result: Box<SignInResult>,
        rotated_trust_cookie: Option<String>,
    },
    Challenge {
        identifier: String,
        methods: Vec<String>,
        max_age_seconds: i64,
    },
}

#[cfg(feature = "axum")]
pub(crate) struct TwoFactorVerification {
    pub result: SignInResult,
    pub remember_me: Option<bool>,
    pub trust_cookie: Option<String>,
}

#[cfg(feature = "axum")]
pub(crate) struct BackupCodeVerification {
    pub completed: Option<TwoFactorVerification>,
    pub user: AuthUser,
    pub token: Option<String>,
}

#[cfg(feature = "axum")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengePayload {
    user_id: uuid::Uuid,
    assurance: crate::Assurance,
    session_expires_at: DateTime<Utc>,
    remember_me: Option<bool>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

#[cfg(feature = "axum")]
#[derive(Clone)]
struct VerificationContext {
    user: AuthUser,
    active: Option<(SessionWithUser, String)>,
    challenge: Option<(String, ChallengePayload)>,
}

#[cfg(feature = "axum")]
impl VerificationContext {
    fn is_sign_in(&self) -> bool {
        self.challenge.is_some()
    }

    fn key(&self) -> String {
        match &self.challenge {
            Some((identifier, _)) => identifier.clone(),
            None => {
                let (session, _) = self.active.as_ref().expect("context has authentication");
                format!("{}!{}", session.user.id, session.session.id)
            }
        }
    }
}

impl AuthService {
    pub(crate) fn two_factor_plugin(&self) -> Result<&TwoFactorPlugin, AuthError> {
        self.plugins
            .find::<TwoFactorPlugin>()
            .ok_or_else(|| AuthError::InvalidConfiguration("two-factor is not enabled".into()))
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn two_factor_enabled(&self, user_id: uuid::Uuid) -> Result<bool, AuthError> {
        let Some(plugin) = self.plugins.find::<TwoFactorPlugin>() else {
            return Ok(false);
        };
        Ok(plugin
            .store
            .find_two_factor(user_id)
            .await?
            .is_some_and(|record| record.enabled))
    }

    #[cfg(feature = "axum")]
    async fn require_two_factor_password(
        &self,
        user_id: uuid::Uuid,
        password: Option<String>,
    ) -> Result<(), AuthError> {
        let plugin = self.two_factor_plugin()?;
        let password_hash = self.store.find_password_hash(user_id).await?;
        match password_hash {
            Some(hash) => {
                let Some(password) = password else {
                    return Err(AuthError::InvalidPassword);
                };
                if !verify_password(password, Some(hash)).await? {
                    return Err(AuthError::InvalidPassword);
                }
            }
            None if plugin.config.allow_passwordless => {}
            None => return Err(AuthError::CredentialAccountNotFound),
        }
        Ok(())
    }

    #[cfg(feature = "axum")]
    async fn assert_two_factor_unlocked(&self, record: &TwoFactorRecord) -> Result<(), AuthError> {
        let plugin = self.two_factor_plugin()?;
        if !plugin.config.account_lockout.enabled {
            return Ok(());
        }
        if record.locked_until.is_some_and(|until| until > Utc::now()) {
            return Err(TwoFactorError::AccountLocked.into());
        }
        if record.locked_until.is_some() {
            plugin
                .store
                .reset_two_factor_failures(record.user_id)
                .await?;
        }
        Ok(())
    }

    #[cfg(feature = "axum")]
    async fn record_two_factor_failure(&self, user_id: uuid::Uuid) -> Result<(), AuthError> {
        let plugin = self.two_factor_plugin()?;
        let config = &plugin.config.account_lockout;
        if config.enabled {
            plugin
                .store
                .record_two_factor_failure(
                    user_id,
                    config.max_failed_attempts,
                    Utc::now() + config.duration,
                )
                .await?;
        }
        Ok(())
    }

    #[cfg(feature = "axum")]
    async fn reset_two_factor_failures(&self, user_id: uuid::Uuid) -> Result<(), AuthError> {
        let plugin = self.two_factor_plugin()?;
        if plugin.config.account_lockout.enabled {
            plugin.store.reset_two_factor_failures(user_id).await?;
        }
        Ok(())
    }
}
