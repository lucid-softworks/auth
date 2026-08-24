use super::{rows::SessionRow, storage_error};
use crate::{AuthError, AuthSession, AuthUser};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub(super) async fn create(pool: &PgPool, session: AuthSession) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO lucid_auth_sessions \
         (id, user_id, token, actor_user_id, authentication_method, expires_at, \
          created_at, updated_at, ip_address, user_agent, additional_fields) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(session.id)
    .bind(session.user_id)
    .bind(&session.token)
    .bind(session.actor_user_id)
    .bind(session.authentication_method.as_str())
    .bind(session.expires_at)
    .bind(session.created_at)
    .bind(session.updated_at)
    .bind(&session.ip_address)
    .bind(&session.user_agent)
    .bind(serde_json::Value::Object(session.additional_fields))
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(storage_error)
}

pub(super) async fn find(
    pool: &PgPool,
    token: &str,
) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
    let session = sqlx::query_as::<_, SessionRow>(
        "SELECT id, user_id, token, actor_user_id, authentication_method, \
         expires_at, created_at, updated_at, ip_address, user_agent, additional_fields \
         FROM lucid_auth_sessions WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .map_err(storage_error)?
    .map(AuthSession::from);
    let Some(session) = session else {
        return Ok(None);
    };
    let user = super::user::load_by_id(pool, session.user_id).await?;
    Ok(user.map(|user| (session, user)))
}

pub(super) async fn find_by_id(
    pool: &PgPool,
    session_id: uuid::Uuid,
) -> Result<Option<AuthSession>, AuthError> {
    sqlx::query_as::<_, SessionRow>(
        "SELECT id, user_id, token, actor_user_id, authentication_method, \
         expires_at, created_at, updated_at, ip_address, user_agent, additional_fields \
         FROM lucid_auth_sessions WHERE id = $1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(AuthSession::from))
    .map_err(storage_error)
}

pub(super) async fn update_fields(
    pool: &PgPool,
    session_id: uuid::Uuid,
    fields: serde_json::Map<String, serde_json::Value>,
) -> Result<Option<AuthSession>, AuthError> {
    sqlx::query_as::<_, SessionRow>(
        "UPDATE lucid_auth_sessions SET additional_fields = additional_fields || $2::jsonb, \
         updated_at = NOW() WHERE id = $1 \
         RETURNING id, user_id, token, actor_user_id, authentication_method, expires_at, \
           created_at, updated_at, ip_address, user_agent, additional_fields",
    )
    .bind(session_id)
    .bind(serde_json::Value::Object(fields))
    .fetch_optional(pool)
    .await
    .map(|row| row.map(AuthSession::from))
    .map_err(storage_error)
}

pub(super) async fn refresh(
    pool: &PgPool,
    token: &str,
    expires_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<Option<AuthSession>, AuthError> {
    sqlx::query_as::<_, SessionRow>(
        "UPDATE lucid_auth_sessions SET expires_at = $2, updated_at = $3 \
         WHERE token = $1 \
         RETURNING id, user_id, token, actor_user_id, authentication_method, expires_at, \
           created_at, updated_at, ip_address, user_agent, additional_fields",
    )
    .bind(token)
    .bind(expires_at)
    .bind(updated_at)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(AuthSession::from))
    .map_err(storage_error)
}

pub(super) async fn delete(pool: &PgPool, token: &str) -> Result<(), AuthError> {
    sqlx::query("DELETE FROM lucid_auth_sessions WHERE token = $1")
        .bind(token)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn delete_expired(pool: &PgPool, now: DateTime<Utc>) -> Result<(), AuthError> {
    sqlx::query("DELETE FROM lucid_auth_sessions WHERE expires_at <= $1")
        .bind(now)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
}
