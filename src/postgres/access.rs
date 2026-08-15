use super::{PostgresStore, SessionRow, UserRow, storage_error};
use crate::{AccessStore, AuditEvent, AuthError, AuthSession, AuthUser, GuestGrant};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
struct GuestGrantRow {
    id: Uuid,
    label: String,
    token_hash: Option<String>,
    permissions: serde_json::Value,
    resource_scopes: serde_json::Value,
    valid_from: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    max_uses: Option<i32>,
    uses: i32,
    created_by: Uuid,
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl TryFrom<GuestGrantRow> for GuestGrant {
    type Error = AuthError;

    fn try_from(row: GuestGrantRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            label: row.label,
            token_hash: row.token_hash,
            permissions: serde_json::from_value(row.permissions)
                .map_err(|error| AuthError::Storage(error.to_string()))?,
            resource_scopes: serde_json::from_value(row.resource_scopes)
                .map_err(|error| AuthError::Storage(error.to_string()))?,
            valid_from: row.valid_from,
            expires_at: row.expires_at,
            max_uses: row.max_uses,
            uses: row.uses,
            created_by: row.created_by,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
        })
    }
}

#[derive(FromRow)]
struct AuditEventRow {
    id: Uuid,
    actor_user_id: Option<Uuid>,
    subject_user_id: Option<Uuid>,
    action: String,
    target: Option<String>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
}

impl From<AuditEventRow> for AuditEvent {
    fn from(row: AuditEventRow) -> Self {
        Self {
            id: row.id,
            actor_user_id: row.actor_user_id,
            subject_user_id: row.subject_user_id,
            action: row.action,
            target: row.target,
            metadata: row.metadata,
            created_at: row.created_at,
        }
    }
}

const USER_COLUMNS: &str = "id, username, display_username, name, email, email_verified, image, \
    role, is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at";
const GRANT_COLUMNS: &str = "id, label, token_hash, permissions, resource_scopes, valid_from, \
    expires_at, max_uses, uses, created_by, revoked_at, created_at";

#[async_trait]
impl AccessStore for PostgresStore {
    async fn list_users(&self, limit: usize, offset: usize) -> Result<Vec<AuthUser>, AuthError> {
        let query = format!(
            "SELECT {USER_COLUMNS} FROM lucid_auth_users ORDER BY created_at LIMIT $1 OFFSET $2"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.into_iter().map(AuthUser::from).collect())
            .map_err(storage_error)
    }

    async fn count_users(&self) -> Result<i64, AuthError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM lucid_auth_users")
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM lucid_auth_users WHERE role = $1")
            .bind(role)
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn update_user_role(&self, user_id: Uuid, role: &str) -> Result<AuthUser, AuthError> {
        let query = format!(
            "UPDATE lucid_auth_users SET role = $2, updated_at = NOW() WHERE id = $1 \
             RETURNING {USER_COLUMNS}"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(user_id)
            .bind(role)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(AuthUser::from)
            .ok_or(AuthError::NotFound)
    }

    async fn update_user_ban(
        &self,
        user_id: Uuid,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthUser, AuthError> {
        let query = format!(
            "UPDATE lucid_auth_users SET banned = $2, ban_reason = $3, ban_expires = $4, \
             updated_at = NOW() WHERE id = $1 RETURNING {USER_COLUMNS}"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(user_id)
            .bind(banned)
            .bind(reason)
            .bind(expires_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(AuthUser::from)
            .ok_or(AuthError::NotFound)
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        let result = sqlx::query("DELETE FROM lucid_auth_users WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<AuthSession>, AuthError> {
        sqlx::query_as::<_, SessionRow>(
            "SELECT id, user_id, token_hash, actor_user_id, guest_grant_id, assurance, \
             expires_at, created_at, updated_at, ip_address, user_agent \
             FROM lucid_auth_sessions WHERE user_id = $1 AND expires_at > NOW() \
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map(|rows| rows.into_iter().map(AuthSession::from).collect())
        .map_err(storage_error)
    }

    async fn delete_session_by_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn create_guest_grant(&self, grant: GuestGrant) -> Result<GuestGrant, AuthError> {
        let query = format!(
            "INSERT INTO lucid_auth_guest_grants \
             (id, label, token_hash, permissions, resource_scopes, valid_from, expires_at, \
              max_uses, uses, created_by, revoked_at, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING {GRANT_COLUMNS}"
        );
        let permissions = serde_json::to_value(&grant.permissions)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        let scopes = serde_json::to_value(&grant.resource_scopes)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        let row = sqlx::query_as::<_, GuestGrantRow>(&query)
            .bind(grant.id)
            .bind(grant.label)
            .bind(grant.token_hash)
            .bind(permissions)
            .bind(scopes)
            .bind(grant.valid_from)
            .bind(grant.expires_at)
            .bind(grant.max_uses)
            .bind(grant.uses)
            .bind(grant.created_by)
            .bind(grant.revoked_at)
            .bind(grant.created_at)
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)?;
        row.try_into()
    }

    async fn consume_guest_grant(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<GuestGrant>, AuthError> {
        let query = format!(
            "UPDATE lucid_auth_guest_grants SET uses = uses + 1 \
             WHERE token_hash = $1 AND revoked_at IS NULL AND valid_from <= $2 \
               AND expires_at > $2 AND (max_uses IS NULL OR uses < max_uses) \
             RETURNING {GRANT_COLUMNS}"
        );
        sqlx::query_as::<_, GuestGrantRow>(&query)
            .bind(token_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(TryInto::try_into)
            .transpose()
    }

    async fn find_guest_grant(&self, grant_id: Uuid) -> Result<Option<GuestGrant>, AuthError> {
        let query = format!("SELECT {GRANT_COLUMNS} FROM lucid_auth_guest_grants WHERE id = $1");
        sqlx::query_as::<_, GuestGrantRow>(&query)
            .bind(grant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(TryInto::try_into)
            .transpose()
    }

    async fn list_guest_grants(&self) -> Result<Vec<GuestGrant>, AuthError> {
        let query =
            format!("SELECT {GRANT_COLUMNS} FROM lucid_auth_guest_grants ORDER BY created_at DESC");
        sqlx::query_as::<_, GuestGrantRow>(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    async fn revoke_guest_grant(
        &self,
        grant_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let result = sqlx::query(
            "UPDATE lucid_auth_guest_grants SET revoked_at = $2, token_hash = NULL WHERE id = $1",
        )
        .bind(grant_id)
        .bind(revoked_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn append_audit_event(&self, event: AuditEvent) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO lucid_auth_audit_events \
             (id, actor_user_id, subject_user_id, action, target, metadata, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(event.id)
        .bind(event.actor_user_id)
        .bind(event.subject_user_id)
        .bind(event.action)
        .bind(event.target)
        .bind(event.metadata)
        .bind(event.created_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    async fn list_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, AuthError> {
        sqlx::query_as::<_, AuditEventRow>(
            "SELECT id, actor_user_id, subject_user_id, action, target, metadata, created_at \
             FROM lucid_auth_audit_events ORDER BY created_at DESC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map(|rows| rows.into_iter().map(AuditEvent::from).collect())
        .map_err(storage_error)
    }
}
