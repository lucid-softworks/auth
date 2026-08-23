#[cfg(feature = "axum")]
pub(crate) mod axum;
pub(crate) mod crypto;
#[cfg(feature = "axum")]
mod http;
mod memory;

pub use memory::MemoryTwoFactorStore;

use crate::{
    AuthConfig, AuthError, AuthPlugin, AuthUser, PluginClientMetadata, PluginCookie,
    PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginMigration, PluginRateLimit,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TwoFactorError {
    #[error("OTP not enabled")]
    OtpNotEnabled,
    #[error("OTP is not available")]
    OtpNotConfigured,
    #[error("OTP has expired")]
    OtpExpired,
    #[error("TOTP not enabled")]
    TotpNotEnabled,
    #[error("TOTP is not available")]
    TotpNotConfigured,
    #[error("two factor is not enabled")]
    NotEnabled,
    #[error("backup codes are not enabled")]
    BackupCodesNotEnabled,
    #[error("invalid backup code")]
    InvalidBackupCode,
    #[error("invalid code")]
    InvalidCode,
    #[error("too many attempts; request a new code")]
    TooManyAttempts,
    #[error("the account is temporarily locked")]
    AccountLocked,
    #[error("invalid two factor cookie")]
    InvalidCookie,
    #[error("the backup code was consumed concurrently")]
    BackupCodeConflict,
}

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint("/two-factor/enable", "twoFactor.enable"),
    endpoint("/two-factor/disable", "twoFactor.disable"),
    endpoint("/two-factor/get-totp-uri", "twoFactor.getTotpUri"),
    endpoint("/two-factor/verify-totp", "twoFactor.verifyTotp"),
    endpoint("/two-factor/send-otp", "twoFactor.sendOtp"),
    endpoint("/two-factor/verify-otp", "twoFactor.verifyOtp"),
    endpoint(
        "/two-factor/generate-backup-codes",
        "twoFactor.generateBackupCodes",
    ),
    endpoint(
        "/two-factor/verify-backup-code",
        "twoFactor.verifyBackupCode",
    ),
];

const fn endpoint(path: &'static str, client_method: &'static str) -> PluginEndpoint {
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path,
        client_method,
    }
}

const COOKIES: &[PluginCookie] = &[
    PluginCookie { name: "two_factor" },
    PluginCookie {
        name: "trust_device",
    },
];

const RATE_LIMITS: &[PluginRateLimit] = &[
    rate_limit("/two-factor/enable"),
    rate_limit("/two-factor/disable"),
    rate_limit("/two-factor/get-totp-uri"),
    rate_limit("/two-factor/verify-totp"),
    rate_limit("/two-factor/send-otp"),
    rate_limit("/two-factor/verify-otp"),
    rate_limit("/two-factor/generate-backup-codes"),
    rate_limit("/two-factor/verify-backup-code"),
];

const fn rate_limit(path: &'static str) -> PluginRateLimit {
    PluginRateLimit {
        path,
        window_seconds: 10,
        max_requests: 3,
    }
}

const MIGRATIONS: &[PluginMigration] = &[PluginMigration {
    id: "better-auth-two-factor-schema",
    description: "Better Auth 1.7.1 two-factor schema",
    sql: include_str!("../../migrations/two_factor_plugin.sql"),
}];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoFactorRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub enabled: bool,
    pub encrypted_secret: Option<String>,
    pub encrypted_backup_codes: Option<String>,
    pub verified: bool,
    pub failed_verification_count: u32,
    pub locked_until: Option<DateTime<Utc>>,
    pub last_totp_counter: Option<i64>,
}

#[async_trait]
pub trait TwoFactorStore: Send + Sync {
    async fn find_two_factor(&self, user_id: Uuid) -> Result<Option<TwoFactorRecord>, AuthError>;

    async fn upsert_two_factor(
        &self,
        record: TwoFactorRecord,
    ) -> Result<TwoFactorRecord, AuthError>;

    async fn delete_two_factor(&self, user_id: Uuid) -> Result<(), AuthError>;

    /// Replaces encrypted backup codes only when the caller's snapshot is current.
    async fn replace_backup_codes(
        &self,
        user_id: Uuid,
        expected: &str,
        replacement: String,
    ) -> Result<bool, AuthError>;

    /// Accepts a TOTP counter exactly once and optionally completes enrollment.
    async fn accept_totp_counter(
        &self,
        user_id: Uuid,
        counter: i64,
        enable: bool,
    ) -> Result<bool, AuthError>;

    /// Atomically increments the account failure budget and returns whether it locked.
    async fn record_two_factor_failure(
        &self,
        user_id: Uuid,
        max_attempts: u32,
        locked_until: DateTime<Utc>,
    ) -> Result<bool, AuthError>;

    async fn reset_two_factor_failures(&self, user_id: Uuid) -> Result<(), AuthError>;
}

#[derive(Debug, Clone)]
pub struct TotpConfig {
    pub disabled: bool,
    pub digits: u32,
    pub period: Duration,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            digits: 6,
            period: Duration::seconds(30),
        }
    }
}

#[derive(Clone)]
pub struct OtpConfig {
    pub sender: Arc<dyn TwoFactorOtpSender>,
    pub digits: usize,
    pub period: Duration,
    pub allowed_attempts: u32,
}

impl OtpConfig {
    pub fn new(sender: Arc<dyn TwoFactorOtpSender>) -> Self {
        Self {
            sender,
            digits: 6,
            period: Duration::minutes(3),
            allowed_attempts: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackupCodeConfig {
    pub amount: usize,
    pub length: usize,
}

impl Default for BackupCodeConfig {
    fn default() -> Self {
        Self {
            amount: 10,
            length: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccountLockoutConfig {
    pub enabled: bool,
    pub max_failed_attempts: u32,
    pub duration: Duration,
}

impl Default for AccountLockoutConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_failed_attempts: 10,
            duration: Duration::minutes(15),
        }
    }
}

#[derive(Clone)]
pub struct TwoFactorConfig {
    pub issuer: Option<String>,
    pub skip_verification_on_enable: bool,
    pub allow_passwordless: bool,
    pub challenge_ttl: Duration,
    pub trust_device_ttl: Duration,
    pub totp: TotpConfig,
    pub otp: Option<OtpConfig>,
    pub backup_codes: BackupCodeConfig,
    pub account_lockout: AccountLockoutConfig,
}

impl Default for TwoFactorConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            skip_verification_on_enable: false,
            allow_passwordless: false,
            challenge_ttl: Duration::minutes(10),
            trust_device_ttl: Duration::days(30),
            totp: TotpConfig::default(),
            otp: None,
            backup_codes: BackupCodeConfig::default(),
            account_lockout: AccountLockoutConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TwoFactorOtp {
    pub user: AuthUser,
    pub code: String,
}

#[async_trait]
pub trait TwoFactorOtpSender: Send + Sync {
    async fn send(&self, otp: TwoFactorOtp) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct TwoFactorPlugin {
    pub(crate) store: Arc<dyn TwoFactorStore>,
    pub(crate) config: Arc<TwoFactorConfig>,
}

impl TwoFactorPlugin {
    pub fn new(store: Arc<dyn TwoFactorStore>, config: TwoFactorConfig) -> Self {
        Self {
            store,
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl AuthPlugin for TwoFactorPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "two-factor",
            display_name: "Better Auth Two-Factor",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: ENDPOINTS,
            cookies: COOKIES,
            rate_limits: RATE_LIMITS,
            middleware: &[],
            client: Some(PluginClientMetadata::current(
                "better-auth",
                "better-auth/client/plugins",
                "twoFactorClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        let config = &self.config;
        if !(1..=8).contains(&config.totp.digits) || config.totp.period <= Duration::zero() {
            return invalid("TOTP digits must be 1-8 and its period must be positive");
        }
        if config.challenge_ttl <= Duration::zero()
            || config.trust_device_ttl <= Duration::zero()
            || config.backup_codes.amount == 0
            || config.backup_codes.length == 0
            || config.account_lockout.max_failed_attempts == 0
            || config.account_lockout.duration <= Duration::zero()
        {
            return invalid(
                "two-factor durations, attempts, and backup-code sizes must be positive",
            );
        }
        if let Some(otp) = &config.otp
            && (otp.digits == 0 || otp.period <= Duration::zero() || otp.allowed_attempts == 0)
        {
            return invalid("OTP digits, expiry, and allowed attempts must be positive");
        }
        if config.totp.disabled && config.otp.is_none() {
            return invalid("two-factor requires TOTP or an OTP sender");
        }
        Ok(())
    }

    fn migrations(&self) -> &'static [PluginMigration] {
        MIGRATIONS
    }

    async fn reset_user_security_state(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.store.delete_two_factor(user_id).await
    }

    async fn after(&self, event: &crate::AfterAuthEvent) {
        if let crate::AfterAuthEvent::UserDeleted { user } = event {
            let _ = self.store.delete_two_factor(user.id).await;
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service)
    }
}

fn invalid<T>(message: &str) -> Result<T, AuthError> {
    Err(AuthError::InvalidConfiguration(message.into()))
}
