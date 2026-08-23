use super::{PostgresStore, storage_error};
use crate::{AuditEvent, AuditMetadata, AuditOutcome, AuditStore, AuthError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
struct AuditEventRow {
    id: Uuid,
    actor_user_id: Option<Uuid>,
    subject_user_id: Option<Uuid>,
    action: String,
    target: Option<String>,
    outcome: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
}

impl TryFrom<AuditEventRow> for AuditEvent {
    type Error = AuthError;

    fn try_from(row: AuditEventRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            actor_user_id: row.actor_user_id,
            subject_user_id: row.subject_user_id,
            action: row.action,
            target: row.target,
            outcome: AuditOutcome::parse(&row.outcome)?,
            metadata: AuditMetadata::new(row.metadata)?,
            created_at: row.created_at,
        })
    }
}

#[async_trait]
impl AuditStore for PostgresStore {
    async fn record_audit_event(&self, event: AuditEvent, retain: usize) -> Result<(), AuthError> {
        let retain = i64::try_from(retain).map_err(|_| {
            AuthError::InvalidConfiguration(
                "audit retention exceeds PostgreSQL's supported range".into(),
            )
        })?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query(
            "INSERT INTO lucid_auth_audit_events \
             (id, actor_user_id, subject_user_id, action, target, outcome, metadata, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(event.id)
        .bind(event.actor_user_id)
        .bind(event.subject_user_id)
        .bind(event.action)
        .bind(event.target)
        .bind(event.outcome.as_str())
        .bind(event.metadata.into_value())
        .bind(event.created_at)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        sqlx::query(
            "DELETE FROM lucid_auth_audit_events WHERE id IN (\
               SELECT id FROM lucid_auth_audit_events ORDER BY created_at DESC, id DESC \
               OFFSET $1\
             )",
        )
        .bind(retain)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn list_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, AuthError> {
        let limit = i64::try_from(limit)
            .map_err(|_| AuthError::InvalidRequest("audit limit is too large".into()))?;
        sqlx::query_as::<_, AuditEventRow>(
            "SELECT id, actor_user_id, subject_user_id, action, target, outcome, metadata, created_at \
             FROM lucid_auth_audit_events ORDER BY created_at DESC, id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
    }

    async fn anonymize_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE lucid_auth_audit_events SET \
             actor_user_id = CASE WHEN actor_user_id = $1 THEN NULL ELSE actor_user_id END, \
             subject_user_id = CASE WHEN subject_user_id = $1 THEN NULL ELSE subject_user_id END \
             WHERE actor_user_id = $1 OR subject_user_id = $1",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }
}
