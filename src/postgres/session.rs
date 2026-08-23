use super::{rows::SessionRow, storage_error};
use crate::{AuthError, AuthSession, AuthUser};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub(super) async fn create(pool: &PgPool, session: AuthSession) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO lucid_auth_sessions \
         (id, user_id, token_hash, actor_user_id, assurance, expires_at, \
          created_at, updated_at, ip_address, user_agent) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(session.id)
    .bind(session.user_id)
    .bind(&session.token_hash)
    .bind(session.actor_user_id)
    .bind(session.assurance.as_str())
    .bind(session.expires_at)
    .bind(session.created_at)
    .bind(session.updated_at)
    .bind(&session.ip_address)
    .bind(&session.user_agent)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(storage_error)
}

pub(super) async fn find(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
    let session = sqlx::query_as::<_, SessionRow>(
        "SELECT id, user_id, token_hash, actor_user_id, assurance, \
         expires_at, created_at, updated_at, ip_address, user_agent \
         FROM lucid_auth_sessions WHERE token_hash = $1",
    )
    .bind(token_hash)
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

pub(super) async fn delete(pool: &PgPool, token_hash: &str) -> Result<(), AuthError> {
    sqlx::query("DELETE FROM lucid_auth_sessions WHERE token_hash = $1")
        .bind(token_hash)
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
