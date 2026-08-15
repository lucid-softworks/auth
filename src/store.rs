use crate::{AuthError, AuthSession, AuthUser, StoredPasskey};
use async_trait::async_trait;
use uuid::Uuid;

/// Persistence boundary required by [`crate::AuthService`].
#[async_trait]
pub trait AuthStore: Send + Sync {
    async fn upsert_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError>;

    async fn create_anonymous_user(&self, user: AuthUser) -> Result<AuthUser, AuthError>;

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError>;

    async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>, AuthError>;

    async fn save_passkey(&self, passkey: StoredPasskey) -> Result<StoredPasskey, AuthError>;

    async fn list_passkeys(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, AuthError>;

    async fn list_all_passkeys(&self) -> Result<Vec<StoredPasskey>, AuthError>;

    async fn update_passkey(&self, passkey: StoredPasskey) -> Result<(), AuthError>;

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<AuthUser>, AuthError>;

    async fn create_session(&self, session: AuthSession) -> Result<(), AuthError>;

    async fn find_session(
        &self,
        token_hash: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError>;

    async fn delete_session(&self, token_hash: &str) -> Result<(), AuthError>;

    async fn delete_expired_sessions(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
}
