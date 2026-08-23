use super::{UserRow, storage_error};
use crate::{AuthError, AuthUser, UserProfileUpdate, UsernameError};
use chrono::Utc;
use sqlx::PgPool;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn load_by_id(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<AuthUser>, AuthError> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, username, display_username, name, email, email_verified, image, role, \
         is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at \
         FROM lucid_auth_users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(AuthUser::from))
    .map_err(storage_error)
}

pub(super) async fn load_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<AuthUser>, AuthError> {
    load_by_column(pool, "username = $1", username).await
}

pub(super) async fn load_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<AuthUser>, AuthError> {
    load_by_column(pool, "LOWER(email) = LOWER($1)", email).await
}

async fn load_by_column(
    pool: &PgPool,
    predicate: &str,
    value: &str,
) -> Result<Option<AuthUser>, AuthError> {
    let query = format!(
        "SELECT id, username, display_username, name, email, email_verified, image, role, \
         is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at \
         FROM lucid_auth_users WHERE {predicate}"
    );
    sqlx::query_as::<_, UserRow>(&query)
        .bind(value)
        .fetch_optional(pool)
        .await
        .map(|row| row.map(AuthUser::from))
        .map_err(storage_error)
}

pub(super) async fn load_by_id_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<Option<AuthUser>, AuthError> {
    sqlx::query_as::<_, UserRow>(
        "SELECT id, username, display_username, name, email, email_verified, image, role, \
         is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at \
         FROM lucid_auth_users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
    .map(|row| row.map(AuthUser::from))
    .map_err(storage_error)
}

pub(super) async fn create_password_user(
    pool: &PgPool,
    mut user: AuthUser,
    password_hash: String,
) -> Result<AuthUser, AuthError> {
    user.email = user.email.to_lowercase();
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let stored = sqlx::query_as::<_, UserRow>(
        "INSERT INTO lucid_auth_users \
         (id, username, display_username, name, email, email_verified, image, role, \
          is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         RETURNING id, username, display_username, name, email, email_verified, image, role, \
           is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at",
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
    .bind(user.must_change_password)
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

pub(super) async fn create_without_account(
    pool: &PgPool,
    mut user: AuthUser,
) -> Result<AuthUser, AuthError> {
    user.email = user.email.to_lowercase();
    sqlx::query_as::<_, UserRow>(
        "INSERT INTO lucid_auth_users \
         (id, username, display_username, name, email, email_verified, image, role, \
          is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         RETURNING id, username, display_username, name, email, email_verified, image, role, \
           is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at",
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
    .bind(user.must_change_password)
    .bind(user.banned)
    .bind(&user.ban_reason)
    .bind(user.ban_expires)
    .bind(user.created_at)
    .bind(user.updated_at)
    .fetch_one(pool)
    .await
    .map(AuthUser::from)
    .map_err(user_insert_error)
}

pub(super) async fn update_profile(
    pool: &PgPool,
    user_id: Uuid,
    update: UserProfileUpdate,
) -> Result<Option<AuthUser>, AuthError> {
    sqlx::query_as::<_, UserRow>(
        "UPDATE lucid_auth_users SET \
         name = COALESCE($2, name), \
         image = CASE WHEN $3 THEN $4 ELSE image END, \
         username = COALESCE($5, username), \
         display_username = COALESCE($6, display_username), \
         updated_at = NOW() WHERE id = $1 \
         RETURNING id, username, display_username, name, email, email_verified, image, role, \
           is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at",
    )
    .bind(user_id)
    .bind(update.name)
    .bind(update.image.is_some())
    .bind(update.image.flatten())
    .bind(update.username)
    .bind(update.display_username)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(AuthUser::from))
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            UsernameError::AlreadyTaken.into()
        } else {
            storage_error(error)
        }
    })
}

pub(super) async fn promote_email_owner(
    pool: &PgPool,
    user_id: Uuid,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<AuthUser>, AuthError> {
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let user = load_by_id_transaction(&mut transaction, user_id).await?;
    let Some(user) = user else {
        transaction.commit().await.map_err(storage_error)?;
        return Ok(None);
    };
    if user.email_verified {
        transaction.commit().await.map_err(storage_error)?;
        return Ok(Some(user));
    }
    sqlx::query("DELETE FROM lucid_auth_accounts WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
    sqlx::query("DELETE FROM lucid_auth_sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
    let user = sqlx::query_as::<_, UserRow>(
        "UPDATE lucid_auth_users SET email_verified = TRUE, updated_at = $2 WHERE id = $1 \
         RETURNING id, username, display_username, name, email, email_verified, image, role, \
           is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at",
    )
    .bind(user_id)
    .bind(now)
    .fetch_one(&mut *transaction)
    .await
    .map(AuthUser::from)
    .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(Some(user))
}

pub(super) async fn set_password_hash(
    pool: &PgPool,
    user_id: Uuid,
    password_hash: String,
) -> Result<(), AuthError> {
    let mut transaction = pool.begin().await.map_err(storage_error)?;
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
    .execute(&mut *transaction)
    .await
    .map_err(storage_error)?;
    let result = sqlx::query(
        "UPDATE lucid_auth_users SET must_change_password = TRUE, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut *transaction)
    .await
    .map_err(storage_error)?;
    if result.rows_affected() == 0 {
        return Err(AuthError::NotFound);
    }
    transaction.commit().await.map_err(storage_error)
}

fn user_insert_error(error: sqlx::Error) -> AuthError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        if error
            .as_database_error()
            .and_then(|database| database.constraint())
            .is_some_and(|constraint| constraint.contains("username"))
        {
            UsernameError::AlreadyTaken.into()
        } else {
            AuthError::UserAlreadyExists
        }
    } else {
        storage_error(error)
    }
}
