use super::{DeviceCode, DeviceCodeOwner, DeviceCodeStatus};
use crate::{AuthError, AuthStore, DatabaseCreate};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum DeviceCodeCreateOutcome {
    Created(DeviceCode),
    UniqueConflict,
}

#[async_trait]
pub trait DeviceAuthorizationStore: Send + Sync {
    async fn create_device_code(
        &self,
        code: DatabaseCreate<DeviceCode>,
        auth_store: &dyn AuthStore,
    ) -> Result<DeviceCodeCreateOutcome, AuthError>;

    async fn find_device_code(&self, device_code: &str) -> Result<Option<DeviceCode>, AuthError>;

    async fn find_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCode>, AuthError>;

    /// Atomically binds an unclaimed pending request to a user.
    async fn bind_pending_user(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<DeviceCode>, AuthError>;

    /// Ordinary polling update performed after the early `slow_down` check.
    async fn update_last_polled_at(
        &self,
        id: &str,
        polled_at: DateTime<Utc>,
    ) -> Result<Option<DeviceCode>, AuthError>;

    /// Ordinary decision update, matching Better Auth 1.7.1's non-CAS write.
    async fn update_device_code_status(
        &self,
        id: &str,
        status: DeviceCodeStatus,
    ) -> Result<Option<DeviceCode>, AuthError>;

    async fn delete_device_code(&self, id: &str) -> Result<Option<DeviceCode>, AuthError>;

    /// Atomically removes one approved record with the expected client owner.
    async fn consume_approved_device_code(
        &self,
        id: &str,
        owner: DeviceCodeOwner,
    ) -> Result<Option<DeviceCode>, AuthError>;
}
