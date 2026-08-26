use crate::{AuthError, AuthUser, DatabaseCreate};
use async_trait::async_trait;

/// Result of an atomic phone-number user write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhoneNumberWriteOutcome<T> {
    Written(T),
    AlreadyExists,
    NotFound,
}

/// Persistence required by the Better Auth phone-number plugin.
#[async_trait]
pub trait PhoneNumberStore: Send + Sync {
    async fn find_user_by_phone_number(
        &self,
        phone_number: &str,
    ) -> Result<Option<AuthUser>, AuthError>;

    async fn create_phone_number_user(
        &self,
        user: DatabaseCreate<AuthUser>,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError>;

    async fn update_user_phone_number(
        &self,
        user_id: &str,
        phone_number: Option<String>,
        verified: bool,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError>;
}
