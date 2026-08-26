use super::{PostgresModel, PostgresStore, storage_error};
use crate::{AuthError, GuestCapabilityStore, GuestGrant};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{FromRow, QueryBuilder, postgres::PgRow};
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
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

fn decode_guest_grant(user: &PostgresModel<'_>, row: &PgRow) -> Result<GuestGrant, AuthError> {
    let grant = GuestGrantRow::from_row(row).map_err(storage_error)?;
    Ok(GuestGrant {
        id: grant.id,
        label: grant.label,
        token_hash: grant.token_hash,
        permissions: serde_json::from_value(grant.permissions)
            .map_err(|error| AuthError::Storage(error.to_string()))?,
        resource_scopes: serde_json::from_value(grant.resource_scopes)
            .map_err(|error| AuthError::Storage(error.to_string()))?,
        valid_from: grant.valid_from,
        expires_at: grant.expires_at,
        max_uses: grant.max_uses,
        uses: grant.uses,
        created_by: user
            .decode_id(row, "created_by")?
            .ok_or_else(|| AuthError::Storage("guest grant creator is null".into()))?,
        revoked_at: grant.revoked_at,
        created_at: grant.created_at,
    })
}

#[async_trait]
impl GuestCapabilityStore for PostgresStore {
    async fn create_guest_grant(&self, grant: GuestGrant) -> Result<GuestGrant, AuthError> {
        let user = self.physical_model("user")?;
        let mut query = QueryBuilder::new(
            "INSERT INTO lucid_auth_guest_grants \
             (id, label, token_hash, permissions, resource_scopes, valid_from, expires_at, \
              max_uses, uses, created_by, revoked_at, created_at) \
             VALUES (",
        );
        let permissions = serde_json::to_value(&grant.permissions)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        let scopes = serde_json::to_value(&grant.resource_scopes)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        query
            .push_bind(grant.id)
            .push(", ")
            .push_bind(grant.label)
            .push(", ")
            .push_bind(grant.token_hash)
            .push(", ")
            .push_bind(permissions)
            .push(", ")
            .push_bind(scopes)
            .push(", ")
            .push_bind(grant.valid_from)
            .push(", ")
            .push_bind(grant.expires_at)
            .push(", ")
            .push_bind(grant.max_uses)
            .push(", ")
            .push_bind(grant.uses)
            .push(", ");
        user.encode("id", json!(grant.created_by))?
            .push_bind(&mut query);
        query
            .push(", ")
            .push_bind(grant.revoked_at)
            .push(", ")
            .push_bind(grant.created_at)
            .push(") RETURNING ")
            .push(GRANT_COLUMNS);
        let row = query
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)?;
        decode_guest_grant(&user, &row)
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
        let user = self.physical_model("user")?;
        sqlx::query(&query)
            .bind(token_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| decode_guest_grant(&user, row))
            .transpose()
    }

    async fn attach_guest_session(
        &self,
        grant_id: Uuid,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let session = self.physical_model("session")?;
        let mut query = QueryBuilder::new(
            "INSERT INTO lucid_auth_guest_grant_sessions (session_id, grant_id) \
             SELECT ",
        );
        session
            .encode("id", json!(session_id))?
            .push_bind(&mut query);
        query
            .push(", id FROM lucid_auth_guest_grants WHERE id = ")
            .push_bind(grant_id)
            .push(" AND revoked_at IS NULL AND valid_from <= ")
            .push_bind(now)
            .push(" AND expires_at > ")
            .push_bind(now)
            .push(" ON CONFLICT (session_id) DO NOTHING");
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)
    }

    async fn find_guest_grant_for_session(
        &self,
        session_id: &str,
    ) -> Result<Option<GuestGrant>, AuthError> {
        let user = self.physical_model("user")?;
        let session = self.physical_model("session")?;
        let mut query = QueryBuilder::new(format!(
            "SELECT {GRANT_COLUMNS} FROM lucid_auth_guest_grants WHERE id = (\
             SELECT grant_id FROM lucid_auth_guest_grant_sessions WHERE session_id = "
        ));
        session
            .encode("id", json!(session_id))?
            .push_bind(&mut query);
        query.push(")");
        query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| decode_guest_grant(&user, row))
            .transpose()
    }

    async fn list_guest_grants(&self) -> Result<Vec<GuestGrant>, AuthError> {
        let user = self.physical_model("user")?;
        let query =
            format!("SELECT {GRANT_COLUMNS} FROM lucid_auth_guest_grants ORDER BY created_at DESC");
        sqlx::query(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .iter()
            .map(|row| decode_guest_grant(&user, row))
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
        let session = self.physical_model("session")?;
        let mut delete_sessions = QueryBuilder::new("DELETE FROM ");
        delete_sessions
            .push(session.quoted_table())
            .push(" WHERE \"id\" IN (SELECT session_id FROM lucid_auth_guest_grant_sessions ")
            .push("WHERE grant_id = ")
            .push_bind(grant_id)
            .push(")");
        delete_sessions
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)
    }
}
