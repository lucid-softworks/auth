#[cfg(feature = "axum")]
mod axum;
mod store;

pub use store::{PhoneNumberStore, PhoneNumberWriteOutcome};

use crate::{
    AdditionalField, AdditionalFieldType, AuthError, AuthPlugin, AuthUser, DatabaseModel,
    PluginClientMetadata, PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginMigration,
    PluginRateLimit, PluginSchemaField,
};
use async_trait::async_trait;
use chrono::Duration;
use serde_json::{Map, Value};
use std::sync::Arc;

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint("/sign-in/phone-number", "signIn.phoneNumber"),
    endpoint("/phone-number/send-otp", "phoneNumber.sendOtp"),
    endpoint("/phone-number/verify", "phoneNumber.verify"),
    endpoint(
        "/phone-number/request-password-reset",
        "phoneNumber.requestPasswordReset",
    ),
    endpoint("/phone-number/reset-password", "phoneNumber.resetPassword"),
];

const RATE_LIMITS: &[PluginRateLimit] = &[
    rate_limit("/phone-number/send-otp"),
    rate_limit("/phone-number/verify"),
    rate_limit("/phone-number/request-password-reset"),
    rate_limit("/phone-number/reset-password"),
];

const MIGRATIONS: &[PluginMigration] = &[PluginMigration::borrowed(
    "better-auth-phone-number-schema",
    "Better Auth 1.7.1 phone-number schema",
    include_str!("../../migrations/phone_number_plugin.sql"),
)];

const fn endpoint(path: &'static str, client_method: &'static str) -> PluginEndpoint {
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed(path),
        client_method,
    }
}

const fn rate_limit(path: &'static str) -> PluginRateLimit {
    PluginRateLimit {
        path,
        window: 60,
        max: 10,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhoneNumberRequestContext {
    pub origin: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneNumberMessage {
    pub phone_number: String,
    pub code: String,
}

#[async_trait]
pub trait PhoneNumberOtpSender: Send + Sync {
    async fn send(
        &self,
        message: PhoneNumberMessage,
        context: PhoneNumberRequestContext,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PhoneNumberOtpVerifier: Send + Sync {
    async fn verify(
        &self,
        phone_number: &str,
        code: &str,
        context: PhoneNumberRequestContext,
    ) -> Result<bool, AuthError>;
}

#[async_trait]
pub trait PhoneNumberValidator: Send + Sync {
    async fn validate(&self, phone_number: &str) -> Result<bool, AuthError>;
}

#[derive(Debug, Clone)]
pub struct PhoneNumberVerified {
    pub phone_number: String,
    pub user: AuthUser,
}

#[async_trait]
pub trait PhoneNumberVerificationCallback: Send + Sync {
    async fn call(
        &self,
        verified: PhoneNumberVerified,
        context: PhoneNumberRequestContext,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PhoneNumberTemporaryEmail: Send + Sync {
    async fn generate(&self, phone_number: &str) -> Result<String, AuthError>;
}

#[async_trait]
pub trait PhoneNumberTemporaryName: Send + Sync {
    async fn generate(&self, phone_number: &str) -> Result<String, AuthError>;
}

#[derive(Clone)]
pub struct PhoneNumberSignUpConfig {
    pub temporary_email: Arc<dyn PhoneNumberTemporaryEmail>,
    pub temporary_name: Option<Arc<dyn PhoneNumberTemporaryName>>,
}

#[derive(Clone)]
pub struct PhoneNumberConfig {
    pub send_otp: Option<Arc<dyn PhoneNumberOtpSender>>,
    pub verify_otp: Option<Arc<dyn PhoneNumberOtpVerifier>>,
    pub send_password_reset_otp: Option<Arc<dyn PhoneNumberOtpSender>>,
    pub otp_length: usize,
    pub expires_in: Duration,
    pub require_verification: bool,
    pub validator: Option<Arc<dyn PhoneNumberValidator>>,
    pub callback_on_verification: Option<Arc<dyn PhoneNumberVerificationCallback>>,
    pub sign_up_on_verification: Option<PhoneNumberSignUpConfig>,
    pub schema: PhoneNumberSchema,
    pub allowed_attempts: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhoneNumberSchema {
    pub phone_number_field_name: Option<String>,
    pub phone_number_verified_field_name: Option<String>,
}

impl Default for PhoneNumberConfig {
    fn default() -> Self {
        Self {
            send_otp: None,
            verify_otp: None,
            send_password_reset_otp: None,
            otp_length: 6,
            expires_in: Duration::seconds(300),
            require_verification: false,
            validator: None,
            callback_on_verification: None,
            sign_up_on_verification: None,
            schema: PhoneNumberSchema::default(),
            allowed_attempts: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PhoneNumberError {
    #[error("Invalid phone number")]
    InvalidPhoneNumber,
    #[error("Phone number already exists")]
    PhoneNumberExists,
    #[error("phone number isn't registered")]
    PhoneNumberNotRegistered,
    #[error("Invalid phone number or password")]
    InvalidPhoneNumberOrPassword,
    #[error("Unexpected error")]
    UnexpectedError,
    #[error("Unexpected error")]
    UnexpectedSignIn,
    #[error("OTP not found")]
    OtpNotFound,
    #[error("OTP expired")]
    OtpExpired,
    #[error("Invalid OTP")]
    InvalidOtp,
    #[error("Phone number not verified")]
    PhoneNumberNotVerified,
    #[error("Phone number cannot be updated")]
    PhoneNumberCannotBeUpdated,
    #[error("sendOTP not implemented")]
    SendOtpNotImplemented,
    #[error("Too many attempts")]
    TooManyAttempts,
    #[error("User not found")]
    UserNotFound,
    #[error("Failed to update user")]
    FailedToUpdateUser,
}

#[derive(Debug, Clone)]
pub struct PhoneNumberSignInInput {
    pub phone_number: String,
    pub password: String,
    pub remember_me: Option<bool>,
    pub origin: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PhoneNumberVerifyInput {
    pub phone_number: String,
    pub code: String,
    pub disable_session: bool,
    pub update_phone_number: bool,
    pub additional_fields: Map<String, Value>,
    pub origin: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PhoneNumberVerification {
    pub token: Option<String>,
    pub user: AuthUser,
}

#[derive(Clone)]
pub struct PhoneNumberPlugin {
    pub(crate) store: Arc<dyn PhoneNumberStore>,
    pub(crate) config: Arc<PhoneNumberConfig>,
}

impl PhoneNumberPlugin {
    pub fn new(store: Arc<dyn PhoneNumberStore>, config: PhoneNumberConfig) -> Self {
        Self {
            store,
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl AuthPlugin for PhoneNumberPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "phone-number",
            display_name: "Better Auth Phone Number",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("phoneNumber"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: RATE_LIMITS,
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "phoneNumberClient",
            )),
        }
    }

    fn migrations(&self) -> std::borrow::Cow<'_, [PluginMigration]> {
        std::borrow::Cow::Borrowed(MIGRATIONS)
    }

    fn schema_fields(&self) -> Vec<PluginSchemaField> {
        let mut phone_number = AdditionalField::new(AdditionalFieldType::String)
            .optional()
            .unique(true)
            .sortable(true);
        if let Some(field_name) = &self.config.schema.phone_number_field_name {
            phone_number = phone_number.field_name(field_name.clone());
        }
        let mut phone_number_verified = AdditionalField::new(AdditionalFieldType::Boolean)
            .optional()
            .input(false);
        if let Some(field_name) = &self.config.schema.phone_number_verified_field_name {
            phone_number_verified = phone_number_verified.field_name(field_name.clone());
        }
        vec![
            PluginSchemaField::new(DatabaseModel::User, "phoneNumber", phone_number),
            PluginSchemaField::new(
                DatabaseModel::User,
                "phoneNumberVerified",
                phone_number_verified,
            ),
        ]
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }
}
