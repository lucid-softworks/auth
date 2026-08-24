use super::{PostgresStore, UserRow, storage_error};
use crate::{
    AuthError, AuthUser, SiweIdentityWrite, SiweIdentityWriteOutcome, SiweSchema, SiweStore,
    WalletAddress, WalletAddressOwner,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

const USER_COLUMNS: &str = "id, username, display_username, name, email, email_verified, image, \
    additional_fields, role, is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at";

#[derive(FromRow)]
struct WalletRow {
    id: Uuid,
    user_id: Uuid,
    address: String,
    chain_id: f64,
    is_primary: bool,
    created_at: DateTime<Utc>,
}

impl From<WalletRow> for WalletAddress {
    fn from(row: WalletRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            address: row.address,
            chain_id: row.chain_id,
            is_primary: row.is_primary,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl SiweStore for PostgresStore {
    async fn find_wallet_owner(
        &self,
        schema: &SiweSchema,
        address: &str,
        chain_id: Option<f64>,
    ) -> Result<Option<WalletAddressOwner>, AuthError> {
        let wallet = find_wallet_pool(&self.pool, schema, address, chain_id).await?;
        let Some(wallet) = wallet else {
            return Ok(None);
        };
        let user = self
            .load_user_by_id(wallet.user_id)
            .await?
            .ok_or_else(|| AuthError::Storage("SIWE wallet owner is missing".into()))?;
        Ok(Some(WalletAddressOwner { wallet, user }))
    }

    async fn write_wallet_identity(
        &self,
        schema: &SiweSchema,
        write: SiweIdentityWrite,
    ) -> Result<SiweIdentityWriteOutcome, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let (wallet, account) = match &write {
            SiweIdentityWrite::Create {
                wallet, account, ..
            }
            | SiweIdentityWrite::AddChain {
                wallet, account, ..
            } => (wallet.clone(), account.as_ref().clone()),
        };
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(lower($1), 0))")
            .bind(&wallet.address)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        if let Some(owner) = find_owner_tx(
            &mut transaction,
            schema,
            &wallet.address,
            Some(wallet.chain_id),
        )
        .await?
        {
            transaction.commit().await.map_err(storage_error)?;
            return Ok(SiweIdentityWriteOutcome::Existing(owner));
        }
        let address_owner = find_owner_tx(&mut transaction, schema, &wallet.address, None).await?;
        let outcome = perform_identity_write(
            &mut transaction,
            schema,
            write,
            wallet,
            account,
            address_owner,
        )
        .await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(outcome)
    }
}

async fn perform_identity_write(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SiweSchema,
    write: SiweIdentityWrite,
    mut wallet: WalletAddress,
    mut account: crate::OAuthAccount,
    address_owner: Option<WalletAddressOwner>,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    match write {
        SiweIdentityWrite::Create { mut user, .. } => {
            if let Some(owner) = address_owner {
                wallet.user_id = owner.user.id;
                wallet.is_primary = false;
                account.user_id = owner.user.id;
                insert_wallet_and_account(transaction, schema, &wallet, &account).await?;
                return Ok(SiweIdentityWriteOutcome::AddedChain {
                    user: owner.user,
                    wallet,
                    account,
                });
            }
            user.email = user.email.to_lowercase();
            if email_exists(transaction, &user.email).await? {
                return Ok(SiweIdentityWriteOutcome::EmailTaken);
            }
            wallet.user_id = user.id;
            wallet.is_primary = true;
            account.user_id = user.id;
            let user = super::oauth::insert_user(transaction, *user).await?;
            insert_wallet_and_account(transaction, schema, &wallet, &account).await?;
            Ok(SiweIdentityWriteOutcome::Created {
                user,
                wallet,
                account,
            })
        }
        SiweIdentityWrite::AddChain {
            expected_user_id, ..
        } => {
            let Some(owner) = address_owner else {
                return Err(AuthError::Storage(
                    "SIWE address owner disappeared during chain linking".into(),
                ));
            };
            if owner.user.id != expected_user_id {
                return Ok(SiweIdentityWriteOutcome::Existing(owner));
            }
            wallet.user_id = owner.user.id;
            wallet.is_primary = false;
            account.user_id = owner.user.id;
            insert_wallet_and_account(transaction, schema, &wallet, &account).await?;
            Ok(SiweIdentityWriteOutcome::AddedChain {
                user: owner.user,
                wallet,
                account,
            })
        }
    }
}

async fn find_wallet_pool(
    pool: &sqlx::PgPool,
    schema: &SiweSchema,
    address: &str,
    chain_id: Option<f64>,
) -> Result<Option<WalletAddress>, AuthError> {
    let sql = WalletSql::new(schema);
    let row = match chain_id {
        Some(chain_id) => {
            sqlx::query_as::<_, WalletRow>(&sql.exact_query())
                .bind(address)
                .bind(chain_id)
                .fetch_optional(pool)
                .await
        }
        None => {
            sqlx::query_as::<_, WalletRow>(&sql.any_query())
                .bind(address)
                .fetch_optional(pool)
                .await
        }
    }
    .map_err(storage_error)?;
    Ok(row.map(WalletAddress::from))
}

async fn find_owner_tx(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SiweSchema,
    address: &str,
    chain_id: Option<f64>,
) -> Result<Option<WalletAddressOwner>, AuthError> {
    let sql = WalletSql::new(schema);
    let wallet = match chain_id {
        Some(chain_id) => {
            sqlx::query_as::<_, WalletRow>(&sql.exact_query())
                .bind(address)
                .bind(chain_id)
                .fetch_optional(&mut **transaction)
                .await
        }
        None => {
            sqlx::query_as::<_, WalletRow>(&sql.any_query())
                .bind(address)
                .fetch_optional(&mut **transaction)
                .await
        }
    }
    .map_err(storage_error)?
    .map(WalletAddress::from);
    let Some(wallet) = wallet else {
        return Ok(None);
    };
    let user = sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLUMNS} FROM lucid_auth_users WHERE id = $1"
    ))
    .bind(wallet.user_id)
    .fetch_one(&mut **transaction)
    .await
    .map(AuthUser::from)
    .map_err(storage_error)?;
    Ok(Some(WalletAddressOwner { wallet, user }))
}

struct WalletSql {
    table: String,
    user_id: String,
    address: String,
    chain_id: String,
    is_primary: String,
    created_at: String,
}

impl WalletSql {
    fn new(schema: &SiweSchema) -> Self {
        Self {
            table: crate::siwe::quote_identifier(schema.table()),
            user_id: crate::siwe::quote_identifier(schema.user_id()),
            address: crate::siwe::quote_identifier(schema.address()),
            chain_id: crate::siwe::quote_identifier(schema.chain_id()),
            is_primary: crate::siwe::quote_identifier(schema.is_primary()),
            created_at: crate::siwe::quote_identifier(schema.created_at()),
        }
    }

    fn columns(&self) -> String {
        format!(
            "id, {} AS user_id, {} AS address, {} AS chain_id, \
             {} AS is_primary, {} AS created_at",
            self.user_id, self.address, self.chain_id, self.is_primary, self.created_at
        )
    }

    fn exact_query(&self) -> String {
        format!(
            "SELECT {} FROM {} WHERE lower({}) = lower($1) AND {} = $2 LIMIT 1",
            self.columns(),
            self.table,
            self.address,
            self.chain_id
        )
    }

    fn any_query(&self) -> String {
        format!(
            "SELECT {} FROM {} WHERE lower({}) = lower($1) \
             ORDER BY {}, id LIMIT 1",
            self.columns(),
            self.table,
            self.address,
            self.created_at
        )
    }
}

async fn email_exists(
    transaction: &mut Transaction<'_, Postgres>,
    email: &str,
) -> Result<bool, AuthError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM lucid_auth_users WHERE email = lower($1))",
    )
    .bind(email)
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)
}

async fn insert_wallet_and_account(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SiweSchema,
    wallet: &WalletAddress,
    account: &crate::OAuthAccount,
) -> Result<(), AuthError> {
    let sql = WalletSql::new(schema);
    let query = format!(
        "INSERT INTO {} (id, {}, {}, {}, {}, {}) VALUES ($1, $2, $3, $4, $5, $6)",
        sql.table, sql.user_id, sql.address, sql.chain_id, sql.is_primary, sql.created_at
    );
    sqlx::query(&query)
        .bind(wallet.id)
        .bind(wallet.user_id)
        .bind(&wallet.address)
        .bind(wallet.chain_id)
        .bind(wallet.is_primary)
        .bind(wallet.created_at)
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    super::oauth::insert_account(transaction, account.clone()).await?;
    Ok(())
}
