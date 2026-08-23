use super::{UserRow, storage_error};
use crate::{
    AccountDeleteOutcome, AuthError, AuthUser, OAuthAccount, OAuthAccountOwner,
    OAuthTokenUpdateOutcome,
};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

const ACCOUNT_COLUMNS: &str = "id, user_id, issuer, account_id, provider_id, access_token, \
    refresh_token, id_token, access_token_expires_at, refresh_token_expires_at, scope, \
    password_hash, created_at, updated_at";

const USER_COLUMNS: &str = "id, username, display_username, name, email, email_verified, image, \
    additional_fields, role, is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at";

#[async_trait::async_trait]
impl crate::OAuthAccountStore for super::PostgresStore {
    async fn find_oauth_account_owner(
        &self,
        issuer: &str,
        account_id: &str,
    ) -> Result<Option<OAuthAccountOwner>, AuthError> {
        find_owner(&self.pool, issuer, account_id).await
    }
    async fn create_oauth_user(
        &self,
        user: AuthUser,
        account: OAuthAccount,
    ) -> Result<OAuthAccountOwner, AuthError> {
        create_user(&self.pool, user, account).await
    }
    async fn link_oauth_account(&self, account: OAuthAccount) -> Result<OAuthAccount, AuthError> {
        link(&self.pool, account).await
    }
    async fn update_oauth_account_tokens(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError> {
        update_tokens(&self.pool, account).await
    }
    async fn list_user_accounts(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AuthError> {
        list(&self.pool, user_id).await
    }
    async fn delete_user_account(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        allow_last: bool,
    ) -> Result<AccountDeleteOutcome, AuthError> {
        delete(&self.pool, user_id, account_id, allow_last).await
    }
    async fn compare_and_swap_oauth_tokens(
        &self,
        account: OAuthAccount,
        expected_refresh_token: Option<&str>,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<OAuthTokenUpdateOutcome, AuthError> {
        compare_and_swap_tokens(
            &self.pool,
            account,
            expected_refresh_token,
            expected_updated_at,
        )
        .await
    }
}

#[derive(FromRow)]
struct AccountRow {
    id: Uuid,
    user_id: Uuid,
    issuer: String,
    account_id: String,
    provider_id: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    access_token_expires_at: Option<DateTime<Utc>>,
    refresh_token_expires_at: Option<DateTime<Utc>>,
    scope: Option<String>,
    password_hash: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<AccountRow> for OAuthAccount {
    fn from(row: AccountRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            issuer: row.issuer,
            account_id: row.account_id,
            provider_id: row.provider_id,
            access_token: row.access_token,
            refresh_token: row.refresh_token,
            id_token: row.id_token,
            access_token_expires_at: row.access_token_expires_at,
            refresh_token_expires_at: row.refresh_token_expires_at,
            scope: row.scope,
            password: row.password_hash,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

pub(super) async fn find_owner(
    pool: &PgPool,
    issuer: &str,
    account_id: &str,
) -> Result<Option<OAuthAccountOwner>, AuthError> {
    let account = sqlx::query_as::<_, AccountRow>(&format!(
        "SELECT {ACCOUNT_COLUMNS} FROM lucid_auth_accounts WHERE issuer = $1 AND account_id = $2"
    ))
    .bind(issuer)
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(storage_error)?;
    let Some(account) = account else {
        return Ok(None);
    };
    let account = OAuthAccount::from(account);
    let user = super::user::load_by_id(pool, account.user_id)
        .await?
        .ok_or_else(|| AuthError::Storage("OAuth account owner is missing".into()))?;
    Ok(Some(OAuthAccountOwner { account, user }))
}

pub(super) async fn create_user(
    pool: &PgPool,
    mut user: AuthUser,
    mut account: OAuthAccount,
) -> Result<OAuthAccountOwner, AuthError> {
    user.email = user.email.to_lowercase();
    account.user_id = user.id;
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let user = insert_user(&mut transaction, user).await?;
    let account = insert_account(&mut transaction, account).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(OAuthAccountOwner { account, user })
}

pub(super) async fn link(pool: &PgPool, account: OAuthAccount) -> Result<OAuthAccount, AuthError> {
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM lucid_auth_users WHERE id = $1)",
    )
    .bind(account.user_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(storage_error)?;
    if !exists {
        return Err(AuthError::NotFound);
    }
    let account = insert_account(&mut transaction, account).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(account)
}

pub(super) async fn update_tokens(
    pool: &PgPool,
    account: OAuthAccount,
) -> Result<OAuthAccount, AuthError> {
    sqlx::query_as::<_, AccountRow>(&format!(
        "UPDATE lucid_auth_accounts SET provider_id = $4, access_token = $5, refresh_token = $6, \
         id_token = $7, access_token_expires_at = $8, refresh_token_expires_at = $9, \
         updated_at = $10 WHERE id = $1 AND issuer = $2 AND account_id = $3 \
         RETURNING {ACCOUNT_COLUMNS}"
    ))
    .bind(account.id)
    .bind(&account.issuer)
    .bind(&account.account_id)
    .bind(&account.provider_id)
    .bind(&account.access_token)
    .bind(&account.refresh_token)
    .bind(&account.id_token)
    .bind(account.access_token_expires_at)
    .bind(account.refresh_token_expires_at)
    .bind(account.updated_at)
    .fetch_optional(pool)
    .await
    .map_err(storage_error)?
    .map(OAuthAccount::from)
    .ok_or(AuthError::NotFound)
}

async fn insert_user(
    transaction: &mut Transaction<'_, Postgres>,
    user: AuthUser,
) -> Result<AuthUser, AuthError> {
    sqlx::query_as::<_, UserRow>(&format!(
        "INSERT INTO lucid_auth_users \
         (id, username, display_username, name, email, email_verified, image, additional_fields, role, \
          is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at) \
         VALUES ($1, NULL, NULL, $2, $3, $4, $5, $6, $7, false, false, NULL, NULL, $8, $8) \
         RETURNING {USER_COLUMNS}"
    ))
    .bind(user.id)
    .bind(user.name)
    .bind(user.email)
    .bind(user.email_verified)
    .bind(user.image)
    .bind(serde_json::Value::Object(user.additional_fields))
    .bind(user.role)
    .bind(user.created_at)
    .fetch_one(&mut **transaction)
    .await
    .map(AuthUser::from)
    .map_err(unique_or_storage)
}

async fn insert_account(
    transaction: &mut Transaction<'_, Postgres>,
    account: OAuthAccount,
) -> Result<OAuthAccount, AuthError> {
    sqlx::query_as::<_, AccountRow>(&format!(
        "INSERT INTO lucid_auth_accounts \
         (id, user_id, issuer, account_id, provider_id, access_token, refresh_token, id_token, \
          access_token_expires_at, refresh_token_expires_at, scope, password_hash, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         RETURNING {ACCOUNT_COLUMNS}"
    ))
    .bind(account.id)
    .bind(account.user_id)
    .bind(account.issuer)
    .bind(account.account_id)
    .bind(account.provider_id)
    .bind(account.access_token)
    .bind(account.refresh_token)
    .bind(account.id_token)
    .bind(account.access_token_expires_at)
    .bind(account.refresh_token_expires_at)
    .bind(account.scope)
    .bind(account.password)
    .bind(account.created_at)
    .bind(account.updated_at)
    .fetch_one(&mut **transaction)
    .await
    .map(OAuthAccount::from)
    .map_err(unique_or_storage)
}

fn unique_or_storage(error: sqlx::Error) -> AuthError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        AuthError::UserAlreadyExists
    } else {
        storage_error(error)
    }
}

pub(super) async fn list(pool: &PgPool, user_id: Uuid) -> Result<Vec<OAuthAccount>, AuthError> {
    sqlx::query_as::<_, AccountRow>(&format!(
        "SELECT {ACCOUNT_COLUMNS} FROM lucid_auth_accounts WHERE user_id = $1 \
         ORDER BY created_at, id"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(OAuthAccount::from).collect())
    .map_err(storage_error)
}

pub(super) async fn delete(
    pool: &PgPool,
    user_id: Uuid,
    account_id: Uuid,
    allow_last: bool,
) -> Result<AccountDeleteOutcome, AuthError> {
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM lucid_auth_accounts WHERE user_id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(storage_error)?;
    if !ids.contains(&account_id) {
        return Ok(AccountDeleteOutcome::NotFound);
    }
    if ids.len() == 1 && !allow_last {
        return Ok(AccountDeleteOutcome::LastAccount);
    }
    sqlx::query("DELETE FROM lucid_auth_accounts WHERE id = $1 AND user_id = $2")
        .bind(account_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(AccountDeleteOutcome::Deleted)
}

pub(super) async fn compare_and_swap_tokens(
    pool: &PgPool,
    account: OAuthAccount,
    expected_refresh_token: Option<&str>,
    expected_updated_at: DateTime<Utc>,
) -> Result<OAuthTokenUpdateOutcome, AuthError> {
    let updated = sqlx::query_as::<_, AccountRow>(&format!(
        "UPDATE lucid_auth_accounts SET access_token = $4, refresh_token = $5, id_token = $6, \
         access_token_expires_at = $7, refresh_token_expires_at = $8, updated_at = $9 \
         WHERE id = $1 AND user_id = $2 AND updated_at = $3 \
         AND refresh_token IS NOT DISTINCT FROM $10 RETURNING {ACCOUNT_COLUMNS}"
    ))
    .bind(account.id)
    .bind(account.user_id)
    .bind(expected_updated_at)
    .bind(&account.access_token)
    .bind(&account.refresh_token)
    .bind(&account.id_token)
    .bind(account.access_token_expires_at)
    .bind(account.refresh_token_expires_at)
    .bind(account.updated_at)
    .bind(expected_refresh_token)
    .fetch_optional(pool)
    .await
    .map_err(storage_error)?;
    if let Some(updated) = updated {
        return Ok(OAuthTokenUpdateOutcome::Updated(updated.into()));
    }
    let current = sqlx::query_as::<_, AccountRow>(&format!(
        "SELECT {ACCOUNT_COLUMNS} FROM lucid_auth_accounts WHERE id = $1 AND user_id = $2"
    ))
    .bind(account.id)
    .bind(account.user_id)
    .fetch_optional(pool)
    .await
    .map_err(storage_error)?;
    Ok(match current {
        Some(current) => OAuthTokenUpdateOutcome::Stale(current.into()),
        None => OAuthTokenUpdateOutcome::NotFound,
    })
}
