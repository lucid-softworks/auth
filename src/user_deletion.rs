use crate::{AuthError, AuthUser};
use async_trait::async_trait;
use chrono::Duration;
use std::{fmt, sync::Arc};

#[derive(Debug, Clone)]
pub struct DeleteAccountVerification {
    pub user: AuthUser,
    pub url: String,
    pub token: String,
}

#[async_trait]
pub trait DeleteAccountVerificationSender: Send + Sync {
    async fn send(&self, verification: DeleteAccountVerification) -> Result<(), AuthError>;
}

#[async_trait]
pub trait UserDeletionCallback: Send + Sync {
    async fn call(&self, user: AuthUser) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct DeleteUserConfig {
    pub enabled: bool,
    pub send_delete_account_verification: Option<Arc<dyn DeleteAccountVerificationSender>>,
    pub before_delete: Option<Arc<dyn UserDeletionCallback>>,
    pub after_delete: Option<Arc<dyn UserDeletionCallback>>,
    pub delete_token_expires_in: Duration,
}

impl Default for DeleteUserConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            send_delete_account_verification: None,
            before_delete: None,
            after_delete: None,
            delete_token_expires_in: Duration::days(1),
        }
    }
}

impl fmt::Debug for DeleteUserConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeleteUserConfig")
            .field("enabled", &self.enabled)
            .field(
                "send_delete_account_verification",
                &self.send_delete_account_verification.is_some(),
            )
            .field("before_delete", &self.before_delete.is_some())
            .field("after_delete", &self.after_delete.is_some())
            .field("delete_token_expires_in", &self.delete_token_expires_in)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct UserConfig {
    pub delete_user: DeleteUserConfig,
}
