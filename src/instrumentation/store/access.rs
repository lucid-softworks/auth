use super::InstrumentedAuthStore;
use crate::{
    AccessStore, AdminListCondition, AdminListUsersQuery, AdminUserUpdate, AuthError, AuthSession,
    AuthUser,
    instrumentation::{AdapterOperation, with_adapter_operation},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl AccessStore for InstrumentedAuthStore {
    async fn list_users(&self, query: &AdminListUsersQuery) -> Result<Vec<AuthUser>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindMany,
            "user",
            self.inner.list_users(query),
        )
        .await
    }

    async fn count_users(&self, conditions: &[AdminListCondition]) -> Result<i64, AuthError> {
        with_adapter_operation(
            AdapterOperation::Count,
            "user",
            self.inner.count_users(conditions),
        )
        .await
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        with_adapter_operation(
            AdapterOperation::Count,
            "user",
            self.inner.count_users_by_role(role),
        )
        .await
    }

    async fn update_user_role(&self, user_id: &str, role: &str) -> Result<AuthUser, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "user",
            self.inner.update_user_role(user_id, role),
        )
        .await
    }

    async fn update_user_ban(
        &self,
        user_id: &str,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthUser, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "user",
            self.inner
                .update_user_ban(user_id, banned, reason, expires_at),
        )
        .await
    }

    async fn admin_update_user(
        &self,
        user_id: &str,
        update: AdminUserUpdate,
    ) -> Result<AuthUser, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "user",
            self.inner.admin_update_user(user_id, update),
        )
        .await
    }

    async fn delete_user(&self, user_id: &str) -> Result<(), AuthError> {
        with_adapter_operation(
            AdapterOperation::Delete,
            "user",
            self.inner.delete_user(user_id),
        )
        .await
    }

    async fn list_sessions(&self, user_id: &str) -> Result<Vec<AuthSession>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindMany,
            "session",
            self.inner.list_sessions(user_id),
        )
        .await
    }

    async fn delete_session_by_id(&self, session_id: &str) -> Result<(), AuthError> {
        with_adapter_operation(
            AdapterOperation::Delete,
            "session",
            self.inner.delete_session_by_id(session_id),
        )
        .await
    }

    async fn delete_user_sessions(&self, user_id: &str) -> Result<(), AuthError> {
        with_adapter_operation(
            AdapterOperation::DeleteMany,
            "session",
            self.inner.delete_user_sessions(user_id),
        )
        .await
    }
}
