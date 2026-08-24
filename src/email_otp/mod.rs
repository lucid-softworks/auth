use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginRateLimit, SignInResult,
};
use async_trait::async_trait;
use chrono::Duration;
use std::sync::Arc;

#[cfg(feature = "axum")]
mod axum;

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(
        "/email-otp/send-verification-otp",
        "emailOtp.sendVerificationOtp",
    ),
    endpoint(
        "/email-otp/check-verification-otp",
        "emailOtp.checkVerificationOtp",
    ),
    endpoint("/email-otp/verify-email", "emailOtp.verifyEmail"),
    endpoint("/sign-in/email-otp", "signIn.emailOtp"),
    endpoint(
        "/email-otp/request-password-reset",
        "emailOtp.requestPasswordReset",
    ),
    endpoint("/forget-password/email-otp", "forgetPassword.emailOtp"),
    endpoint("/email-otp/reset-password", "emailOtp.resetPassword"),
    endpoint(
        "/email-otp/request-email-change",
        "emailOtp.requestEmailChange",
    ),
    endpoint("/email-otp/change-email", "emailOtp.changeEmail"),
];

const fn endpoint(path: &'static str, client_method: &'static str) -> PluginEndpoint {
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path,
        client_method,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailOtpType {
    EmailVerification,
    SignIn,
    ForgetPassword,
    ChangeEmail,
}

impl EmailOtpType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email-verification",
            Self::SignIn => "sign-in",
            Self::ForgetPassword => "forget-password",
            Self::ChangeEmail => "change-email",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailOtpMessage {
    pub email: String,
    pub otp: String,
    pub kind: EmailOtpType,
}

#[derive(Debug, Clone)]
pub struct EmailOtpVerification {
    pub user: crate::AuthUser,
    pub session: Option<SignInResult>,
}

#[derive(Debug, Clone)]
pub struct EmailOtpSignInInput {
    pub email: String,
    pub otp: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmailOtpRequestContext {
    pub origin: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[async_trait]
pub trait EmailOtpSender: Send + Sync {
    async fn send(
        &self,
        message: EmailOtpMessage,
        context: EmailOtpRequestContext,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait EmailOtpGenerator: Send + Sync {
    async fn generate(&self, email: &str, kind: EmailOtpType) -> Result<String, AuthError>;
}

#[async_trait]
pub trait EmailOtpHasher: Send + Sync {
    async fn hash(&self, otp: &str) -> Result<String, AuthError>;
}

#[async_trait]
pub trait EmailOtpEncryptor: Send + Sync {
    async fn encrypt(&self, otp: &str) -> Result<String, AuthError>;
    async fn decrypt(&self, stored_otp: &str) -> Result<String, AuthError>;
}

#[derive(Clone, Default)]
pub enum EmailOtpStorage {
    #[default]
    Plain,
    Hashed,
    Encrypted,
    CustomHash(Arc<dyn EmailOtpHasher>),
    CustomEncryption(Arc<dyn EmailOtpEncryptor>),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EmailOtpResendStrategy {
    #[default]
    Rotate,
    Reuse,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmailOtpChangeEmailConfig {
    pub enabled: bool,
    pub verify_current_email: bool,
}

#[derive(Clone)]
pub struct EmailOtpConfig {
    pub sender: Arc<dyn EmailOtpSender>,
    pub otp_length: usize,
    pub expires_in: Duration,
    pub generator: Option<Arc<dyn EmailOtpGenerator>>,
    pub send_verification_on_sign_up: bool,
    pub disable_sign_up: bool,
    pub allowed_attempts: u32,
    pub storage: EmailOtpStorage,
    pub resend_strategy: EmailOtpResendStrategy,
    pub change_email: EmailOtpChangeEmailConfig,
    pub override_default_email_verification: bool,
    pub rate_limit_window: Duration,
    pub rate_limit_max: usize,
}

impl EmailOtpConfig {
    pub fn new(sender: Arc<dyn EmailOtpSender>) -> Self {
        Self {
            sender,
            otp_length: 6,
            expires_in: Duration::seconds(300),
            generator: None,
            send_verification_on_sign_up: false,
            disable_sign_up: false,
            allowed_attempts: 3,
            storage: EmailOtpStorage::Plain,
            resend_strategy: EmailOtpResendStrategy::Rotate,
            change_email: EmailOtpChangeEmailConfig::default(),
            override_default_email_verification: false,
            rate_limit_window: Duration::seconds(60),
            rate_limit_max: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EmailOtpError {
    #[error("Invalid OTP")]
    InvalidOtp,
    #[error("OTP expired")]
    OtpExpired,
    #[error("Too many attempts")]
    TooManyAttempts,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid OTP type")]
    InvalidOtpType,
    #[error("Change email with OTP is disabled")]
    ChangeEmailDisabled,
    #[error("OTP is required to verify current email")]
    CurrentEmailOtpRequired,
    #[error("Email is the same")]
    EmailIsSame,
    #[error("Email already in use")]
    EmailAlreadyInUse,
    #[error("OTP is hashed, cannot return the plain text OTP")]
    HashedOtpUnavailable,
}

#[derive(Clone)]
pub struct EmailOtpPlugin {
    pub(crate) config: Arc<EmailOtpConfig>,
}

impl EmailOtpPlugin {
    pub fn new(config: EmailOtpConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl AuthPlugin for EmailOtpPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "email-otp",
            display_name: "Better Auth Email OTP",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: ENDPOINTS,
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::current(
                "better-auth",
                "better-auth/client/plugins",
                "emailOTPClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        if self.config.otp_length == 0
            || self.config.expires_in <= Duration::zero()
            || self.config.allowed_attempts == 0
            || self.config.rate_limit_window <= Duration::zero()
            || self.config.rate_limit_max == 0
        {
            return Err(AuthError::InvalidConfiguration(
                "email-OTP length, expiry, attempts, and rate-limit values must be positive".into(),
            ));
        }
        Ok(())
    }

    fn rate_limits(&self) -> Vec<PluginRateLimit> {
        let window = u64::try_from(self.config.rate_limit_window.num_seconds()).unwrap_or(u64::MAX);
        let max = u32::try_from(self.config.rate_limit_max).unwrap_or(u32::MAX);
        ENDPOINTS
            .iter()
            .map(|endpoint| PluginRateLimit {
                path: endpoint.path,
                window,
                max,
            })
            .collect()
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }
}
