use crate::{AuthError, AuthUser};
use async_trait::async_trait;
use chrono::Duration;
use std::sync::Arc;

/// Secret-bearing payload delivered only to the configured native sender.
#[derive(Clone)]
pub struct VerificationEmail {
    pub user: AuthUser,
    pub url: String,
    pub token: String,
}

#[async_trait]
pub trait VerificationEmailSender: Send + Sync {
    async fn send(&self, email: VerificationEmail) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct PasswordResetEmail {
    pub user: AuthUser,
    pub url: String,
    pub token: String,
}

#[async_trait]
pub trait PasswordResetEmailSender: Send + Sync {
    async fn send(&self, email: PasswordResetEmail) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PasswordResetCallback: Send + Sync {
    async fn on_password_reset(&self, user: AuthUser) -> Result<(), AuthError>;
}

/// Better Auth 1.7.1 email-verification settings.
#[derive(Clone)]
pub struct EmailVerificationConfig {
    pub sender: Option<Arc<dyn VerificationEmailSender>>,
    pub send_on_sign_up: Option<bool>,
    pub send_on_sign_in: bool,
    pub auto_sign_in_after_verification: bool,
    pub expires_in: Duration,
}

impl Default for EmailVerificationConfig {
    fn default() -> Self {
        Self {
            sender: None,
            send_on_sign_up: None,
            send_on_sign_in: false,
            auto_sign_in_after_verification: false,
            expires_in: Duration::hours(1),
        }
    }
}
