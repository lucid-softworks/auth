use super::{UserRow, storage_error};
use crate::{AuthError, AuthUser};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn load_by_id(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<AuthUser>, AuthError> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, username, display_username, name, email, email_verified, image, role, \
         is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at \
         FROM lucid_auth_users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(AuthUser::from))
    .map_err(storage_error)
}

pub(super) async fn create_password_user(
    pool: &PgPool,
    user: AuthUser,
    password_hash: String,
) -> Result<AuthUser, AuthError> {
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let stored = sqlx::query_as::<_, UserRow>(
        "INSERT INTO lucid_auth_users \
         (id, username, display_username, name, email, email_verified, image, role, \
          is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         RETURNING id, username, display_username, name, email, email_verified, image, role, \
           is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at",
    )
    .bind(user.id)
    .bind(&user.username)
    .bind(&user.display_username)
    .bind(&user.name)
    .bind(&user.email)
    .bind(user.email_verified)
    .bind(&user.image)
    .bind(&user.role)
    .bind(user.is_anonymous)
    .bind(user.banned)
    .bind(&user.ban_reason)
    .bind(user.ban_expires)
    .bind(user.created_at)
    .bind(user.updated_at)
    .fetch_one(&mut *transaction)
    .await
    .map_err(user_insert_error)?;
    sqlx::query(
        "INSERT INTO lucid_auth_accounts \
         (id, user_id, provider_id, account_id, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'credential', $3, $4, $5, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(stored.id)
    .bind(stored.id.to_string())
    .bind(password_hash)
    .bind(Utc::now())
    .execute(&mut *transaction)
    .await
    .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(AuthUser::from(stored))
}

pub(super) async fn set_password_hash(
    pool: &PgPool,
    user_id: Uuid,
    password_hash: String,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO lucid_auth_accounts \
         (id, user_id, provider_id, account_id, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'credential', $3, $4, NOW(), NOW()) \
         ON CONFLICT (user_id, provider_id) DO UPDATE SET \
           password_hash = EXCLUDED.password_hash, updated_at = NOW()",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(user_id.to_string())
    .bind(password_hash)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(storage_error)
}

fn user_insert_error(error: sqlx::Error) -> AuthError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        AuthError::UserAlreadyExists
    } else {
        storage_error(error)
    }
}
