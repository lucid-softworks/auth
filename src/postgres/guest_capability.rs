use super::{PostgresStore, storage_error};
use crate::{AuthError, GuestCapabilityStore, GuestGrant};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

const GRANT_COLUMNS: &str = "id, label, token_hash, permissions, resource_scopes, valid_from, \
    expires_at, max_uses, uses, created_by, revoked_at, created_at";

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

#[async_trait]
impl GuestCapabilityStore for PostgresStore {
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
        sqlx::query_as::<_, GuestGrantRow>(&query)
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
            .map_err(storage_error)?
            .try_into()
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

    async fn attach_guest_session(
        &self,
        grant_id: Uuid,
        session_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        sqlx::query(
            "INSERT INTO lucid_auth_guest_grant_sessions (session_id, grant_id) \
             SELECT $2, id FROM lucid_auth_guest_grants \
             WHERE id = $1 AND revoked_at IS NULL AND valid_from <= $3 AND expires_at > $3 \
             ON CONFLICT (session_id) DO NOTHING",
        )
        .bind(grant_id)
        .bind(session_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(storage_error)
    }

    async fn find_guest_grant_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<GuestGrant>, AuthError> {
        let query = format!(
            "SELECT {GRANT_COLUMNS} FROM lucid_auth_guest_grants \
             WHERE id = (SELECT grant_id FROM lucid_auth_guest_grant_sessions \
                         WHERE session_id = $1)"
        );
        sqlx::query_as::<_, GuestGrantRow>(&query)
            .bind(session_id)
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
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let result = sqlx::query(
            "UPDATE lucid_auth_guest_grants SET revoked_at = $2, token_hash = NULL WHERE id = $1",
        )
        .bind(grant_id)
        .bind(revoked_at)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        sqlx::query(
            "DELETE FROM lucid_auth_sessions WHERE id IN (\
               SELECT session_id FROM lucid_auth_guest_grant_sessions WHERE grant_id = $1\
             )",
        )
        .bind(grant_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)
    }
}
