mod account;

use super::{PostgresModel, PostgresStore, storage_error};
use crate::{
    AccountDeleteOutcome, AuthError, AuthUser, OAuthAccount, OAuthAccountOwner,
    OAuthTokenUpdateOutcome,
};
use account::{decode_account, token_writes};
pub(super) use account::{insert_account_transaction, upsert_account_transaction};
use chrono::{DateTime, Utc};
use sqlx::QueryBuilder;
use uuid::Uuid;

impl PostgresStore {
    pub(super) fn account_model(&self) -> Result<PostgresModel<'_>, AuthError> {
        self.physical_model("account")
    }
}

#[async_trait::async_trait]
impl crate::OAuthAccountStore for PostgresStore {
    async fn find_oauth_account_owner(
        &self,
        issuer: &str,
        account_id: &str,
    ) -> Result<Option<OAuthAccountOwner>, AuthError> {
        find_owner(self, issuer, account_id).await
    }

    async fn create_oauth_user(
        &self,
        user: AuthUser,
        account: OAuthAccount,
    ) -> Result<OAuthAccountOwner, AuthError> {
        create_user(self, user, account).await
    }

    async fn link_oauth_account(&self, account: OAuthAccount) -> Result<OAuthAccount, AuthError> {
        link(self, account).await
    }

    async fn update_oauth_account_tokens(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError> {
        update_tokens(self, account).await
    }

    async fn list_user_accounts(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AuthError> {
        list(self, user_id).await
    }

    async fn delete_user_account(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        allow_last: bool,
    ) -> Result<AccountDeleteOutcome, AuthError> {
        delete(self, user_id, account_id, allow_last).await
    }

    async fn compare_and_swap_oauth_tokens(
        &self,
        account: OAuthAccount,
        expected_refresh_token: Option<&str>,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<OAuthTokenUpdateOutcome, AuthError> {
        compare_and_swap_tokens(self, account, expected_refresh_token, expected_updated_at).await
    }
}

async fn find_owner(
    store: &PostgresStore,
    issuer: &str,
    account_id: &str,
) -> Result<Option<OAuthAccountOwner>, AuthError> {
    let model = store.account_model()?;
    let mut query = super::rows::select_query(&model);
    query
        .push(" WHERE ")
        .push(model.quoted_column("issuer")?)
        .push(" = ")
        .push_bind(issuer.to_owned())
        .push(" AND ")
        .push(model.quoted_column("accountId")?)
        .push(" = ")
        .push_bind(account_id.to_owned());
    let row = query
        .build()
        .fetch_optional(&store.pool)
        .await
        .map_err(storage_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let account = decode_account(&model, &row)?;
    let user = super::user::load_by_id(store, account.user_id)
        .await?
        .ok_or_else(|| AuthError::Storage("OAuth account owner is missing".into()))?;
    Ok(Some(OAuthAccountOwner { account, user }))
}

async fn create_user(
    store: &PostgresStore,
    mut user: AuthUser,
    mut account: OAuthAccount,
) -> Result<OAuthAccountOwner, AuthError> {
    user.email = user.email.to_lowercase();
    account.user_id = user.id;
    let user_model = store.user_model()?;
    let account_model = store.account_model()?;
    let mut transaction = store.pool.begin().await.map_err(storage_error)?;
    let user = super::user::insert_transaction(&mut transaction, &user_model, user).await?;
    let account = insert_account_transaction(&mut transaction, &account_model, &account).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(OAuthAccountOwner { account, user })
}

async fn link(store: &PostgresStore, account: OAuthAccount) -> Result<OAuthAccount, AuthError> {
    let user_model = store.user_model()?;
    let account_model = store.account_model()?;
    let mut transaction = store.pool.begin().await.map_err(storage_error)?;
    let mut exists = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    exists
        .push(user_model.quoted_table())
        .push(" WHERE \"id\" = ")
        .push_bind(account.user_id)
        .push(")");
    if !exists
        .build_query_scalar::<bool>()
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?
    {
        return Err(AuthError::NotFound);
    }
    let account = insert_account_transaction(&mut transaction, &account_model, &account).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(account)
}

async fn update_tokens(
    store: &PostgresStore,
    account: OAuthAccount,
) -> Result<OAuthAccount, AuthError> {
    let model = store.account_model()?;
    let writes = token_writes(&model, &account)?;
    let mut query = super::rows::update_query(&model, writes);
    query
        .push(" WHERE \"id\" = ")
        .push_bind(account.id)
        .push(" AND ")
        .push(model.quoted_column("issuer")?)
        .push(" = ")
        .push_bind(account.issuer.clone())
        .push(" AND ")
        .push(model.quoted_column("accountId")?)
        .push(" = ")
        .push_bind(account.account_id.clone())
        .push(" RETURNING ")
        .push(model.all_projection());
    let row = query
        .build()
        .fetch_optional(&store.pool)
        .await
        .map_err(storage_error)?
        .ok_or(AuthError::NotFound)?;
    decode_account(&model, &row)
}

async fn list(store: &PostgresStore, user_id: Uuid) -> Result<Vec<OAuthAccount>, AuthError> {
    let model = store.account_model()?;
    let mut query = super::rows::select_query(&model);
    query
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ")
        .push_bind(user_id)
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?)
        .push(", \"id\"");
    query
        .build()
        .fetch_all(&store.pool)
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| decode_account(&model, row))
        .collect()
}

async fn delete(
    store: &PostgresStore,
    user_id: Uuid,
    account_id: Uuid,
    allow_last: bool,
) -> Result<AccountDeleteOutcome, AuthError> {
    let model = store.account_model()?;
    let mut transaction = store.pool.begin().await.map_err(storage_error)?;
    let mut select = QueryBuilder::new("SELECT \"id\" FROM ");
    select
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ")
        .push_bind(user_id)
        .push(" FOR UPDATE");
    let ids: Vec<Uuid> = select
        .build_query_scalar()
        .fetch_all(&mut *transaction)
        .await
        .map_err(storage_error)?;
    if !ids.contains(&account_id) {
        return Ok(AccountDeleteOutcome::NotFound);
    }
    if ids.len() == 1 && !allow_last {
        return Ok(AccountDeleteOutcome::LastAccount);
    }
    let mut delete = QueryBuilder::new("DELETE FROM ");
    delete
        .push(model.quoted_table())
        .push(" WHERE \"id\" = ")
        .push_bind(account_id)
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ")
        .push_bind(user_id);
    delete
        .build()
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(AccountDeleteOutcome::Deleted)
}

async fn compare_and_swap_tokens(
    store: &PostgresStore,
    account: OAuthAccount,
    expected_refresh_token: Option<&str>,
    expected_updated_at: DateTime<Utc>,
) -> Result<OAuthTokenUpdateOutcome, AuthError> {
    let model = store.account_model()?;
    let writes = token_writes(&model, &account)?;
    let mut query = super::rows::update_query(&model, writes);
    query
        .push(" WHERE \"id\" = ")
        .push_bind(account.id)
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ")
        .push_bind(account.user_id)
        .push(" AND ")
        .push(model.quoted_column("updatedAt")?)
        .push(" = ")
        .push_bind(expected_updated_at)
        .push(" AND ")
        .push(model.quoted_column("refreshToken")?)
        .push(" IS NOT DISTINCT FROM ")
        .push_bind(expected_refresh_token.map(str::to_owned))
        .push(" RETURNING ")
        .push(model.all_projection());
    if let Some(updated) = query
        .build()
        .fetch_optional(&store.pool)
        .await
        .map_err(storage_error)?
    {
        return Ok(OAuthTokenUpdateOutcome::Updated(decode_account(
            &model, &updated,
        )?));
    }
    let mut current = super::rows::select_query(&model);
    current
        .push(" WHERE \"id\" = ")
        .push_bind(account.id)
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ")
        .push_bind(account.user_id);
    let current = current
        .build()
        .fetch_optional(&store.pool)
        .await
        .map_err(storage_error)?;
    Ok(match current {
        Some(current) => OAuthTokenUpdateOutcome::Stale(decode_account(&model, &current)?),
        None => OAuthTokenUpdateOutcome::NotFound,
    })
}
