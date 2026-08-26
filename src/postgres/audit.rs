use super::{PostgresModel, PostgresStore, storage_error};
use crate::{AuditEvent, AuditMetadata, AuditOutcome, AuditStore, AuthError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{FromRow, QueryBuilder, postgres::PgRow};
use uuid::Uuid;

#[derive(FromRow)]
struct AuditEventRow {
    id: Uuid,
    action: String,
    target: Option<String>,
    outcome: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
}

fn decode_audit_event(user: &PostgresModel<'_>, row: &PgRow) -> Result<AuditEvent, AuthError> {
    let event = AuditEventRow::from_row(row).map_err(storage_error)?;
    Ok(AuditEvent {
        id: event.id,
        actor_user_id: user.decode_id(row, "actor_user_id")?,
        subject_user_id: user.decode_id(row, "subject_user_id")?,
        action: event.action,
        target: event.target,
        outcome: AuditOutcome::parse(&event.outcome)?,
        metadata: AuditMetadata::new(event.metadata)?,
        created_at: event.created_at,
    })
}

#[async_trait]
impl AuditStore for PostgresStore {
    async fn record_audit_event(&self, event: AuditEvent, retain: usize) -> Result<(), AuthError> {
        let retain = i64::try_from(retain).map_err(|_| {
            AuthError::InvalidConfiguration(
                "audit retention exceeds PostgreSQL's supported range".into(),
            )
        })?;
        let user = self.physical_model("user")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let mut insert = QueryBuilder::new(
            "INSERT INTO lucid_auth_audit_events \
             (id, actor_user_id, subject_user_id, action, target, outcome, metadata, created_at) \
             VALUES (",
        );
        insert.push_bind(event.id).push(", ");
        user.encode("id", json!(event.actor_user_id))?
            .push_bind(&mut insert);
        insert.push(", ");
        user.encode("id", json!(event.subject_user_id))?
            .push_bind(&mut insert);
        insert
            .push(", ")
            .push_bind(event.action)
            .push(", ")
            .push_bind(event.target)
            .push(", ")
            .push_bind(event.outcome.as_str())
            .push(", ")
            .push_bind(event.metadata.into_value())
            .push(", ")
            .push_bind(event.created_at)
            .push(")");
        insert
            .build()
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
        let user = self.physical_model("user")?;
        sqlx::query(
            "SELECT id, actor_user_id, subject_user_id, action, target, outcome, metadata, created_at \
             FROM lucid_auth_audit_events ORDER BY created_at DESC, id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| decode_audit_event(&user, row))
        .collect()
    }

    async fn anonymize_user(&self, user_id: &str) -> Result<(), AuthError> {
        let user = self.physical_model("user")?;
        let mut query = QueryBuilder::new(
            "UPDATE lucid_auth_audit_events SET \
             actor_user_id = CASE WHEN actor_user_id = ",
        );
        user.encode("id", json!(user_id))?.push_bind(&mut query);
        query.push(
            " THEN NULL ELSE actor_user_id END, subject_user_id = CASE WHEN subject_user_id = ",
        );
        user.encode("id", json!(user_id))?.push_bind(&mut query);
        query.push(" THEN NULL ELSE subject_user_id END WHERE actor_user_id = ");
        user.encode("id", json!(user_id))?.push_bind(&mut query);
        query.push(" OR subject_user_id = ");
        user.encode("id", json!(user_id))?.push_bind(&mut query);
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }
}
