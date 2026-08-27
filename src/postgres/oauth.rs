mod account;

use super::{PostgresModel, PostgresStore, storage_error};
use crate::{
    AccountDeleteOutcome, AuthError, AuthUser, OAuthAccount, OAuthAccountOwner,
    OAuthTokenUpdateOutcome,
};
use account::token_writes;
pub(in crate::postgres) use account::{account_writes, decode_account};
pub(in crate::postgres) use account::{
    find_credential_account_transaction, update_account_transaction,
};
pub(super) use account::{insert_account_transaction, upsert_account_transaction};
use chrono::{DateTime, Utc};
use sqlx::QueryBuilder;

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
        user: crate::store::DatabaseCreate<AuthUser>,
        account: &dyn crate::store::DependentAccountPreparer,
    ) -> Result<OAuthAccountOwner, AuthError> {
        create_user(self, user, account).await
    }

    async fn link_oauth_account(
        &self,
        account: crate::store::DatabaseCreate<OAuthAccount>,
    ) -> Result<OAuthAccount, AuthError> {
        link(self, account).await
    }

    async fn update_oauth_account_tokens(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError> {
        update_tokens(self, account).await
    }

    async fn list_user_accounts(&self, user_id: &str) -> Result<Vec<OAuthAccount>, AuthError> {
        list(self, user_id).await
    }

    async fn delete_user_account(
        &self,
        user_id: &str,
        account_id: &str,
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
    let user = super::user::load_by_id(store, &account.user_id)
        .await?
        .ok_or_else(|| AuthError::Storage("OAuth account owner is missing".into()))?;
    Ok(Some(OAuthAccountOwner { account, user }))
}

async fn create_user(
    store: &PostgresStore,
    user: crate::store::DatabaseCreate<AuthUser>,
    account: &dyn crate::store::DependentAccountPreparer,
) -> Result<OAuthAccountOwner, AuthError> {
    let (user, user_id) = user.into_parts(store)?;
    let user_model = store.user_model()?;
    let account_model = store.account_model()?;
    let mut transaction = store.pool.begin().await.map_err(storage_error)?;
    let user =
        super::user::insert_transaction(&mut transaction, &user_model, user, &user_id).await?;
    let account = account
        .prepare_account(crate::DependentAccountContext {
            user: &user,
            user_operation: crate::DatabaseWriteOperation::Create,
            existing_account: None,
        })
        .await?;
    let crate::DatabaseWrite::Create(account) = account else {
        return Err(AuthError::Storage(
            "fresh OAuth user preparer returned an account update".into(),
        ));
    };
    let (mut account, account_id) = account.into_parts(store)?;
    account.user_id = user.id.clone();
    let account =
        insert_account_transaction(&mut transaction, &account_model, &account, &account_id).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(OAuthAccountOwner { account, user })
}

async fn link(
    store: &PostgresStore,
    account: crate::store::DatabaseCreate<OAuthAccount>,
) -> Result<OAuthAccount, AuthError> {
    let user_id = account.record.user_id.clone();
    let user_model = store.user_model()?;
    let account_model = store.account_model()?;
    let mut transaction = store.pool.begin().await.map_err(storage_error)?;
    let mut exists = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    exists
        .push(user_model.quoted_table())
        .push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut exists, &user_model, "id", serde_json::json!(user_id))?;
    exists.push(")");
    if !exists
        .build_query_scalar::<bool>()
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?
    {
        return Err(AuthError::NotFound);
    }
    let (account, account_id) = account.into_parts(store)?;
    let account =
        insert_account_transaction(&mut transaction, &account_model, &account, &account_id).await?;
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
    query.push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut query, &model, "id", serde_json::json!(account.id))?;
    query
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

async fn list(store: &PostgresStore, user_id: &str) -> Result<Vec<OAuthAccount>, AuthError> {
    let model = store.account_model()?;
    let mut query = super::rows::select_query(&model);
    query
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    super::rows::push_model_value(&mut query, &model, "userId", serde_json::json!(user_id))?;
    query
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
    user_id: &str,
    account_id: &str,
    allow_last: bool,
) -> Result<AccountDeleteOutcome, AuthError> {
    let model = store.account_model()?;
    let mut transaction = store.pool.begin().await.map_err(storage_error)?;
    let mut select = super::rows::select_query(&model);
    select
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    super::rows::push_model_value(&mut select, &model, "userId", serde_json::json!(user_id))?;
    select.push(" FOR UPDATE");
    let rows = select
        .build()
        .fetch_all(&mut *transaction)
        .await
        .map_err(storage_error)?;
    let accounts = rows
        .iter()
        .map(|row| decode_account(&model, row))
        .collect::<Result<Vec<_>, _>>()?;
    if !accounts.iter().any(|account| account.id == account_id) {
        return Ok(AccountDeleteOutcome::NotFound);
    }
    if accounts.len() == 1 && !allow_last {
        return Ok(AccountDeleteOutcome::LastAccount);
    }
    let mut delete = QueryBuilder::new("DELETE FROM ");
    delete.push(model.quoted_table()).push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut delete, &model, "id", serde_json::json!(account_id))?;
    delete
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    super::rows::push_model_value(&mut delete, &model, "userId", serde_json::json!(user_id))?;
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
    query.push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut query, &model, "id", serde_json::json!(account.id))?;
    query
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    super::rows::push_model_value(
        &mut query,
        &model,
        "userId",
        serde_json::json!(account.user_id),
    )?;
    query
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
    current.push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut current, &model, "id", serde_json::json!(account.id))?;
    current
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    super::rows::push_model_value(
        &mut current,
        &model,
        "userId",
        serde_json::json!(account.user_id),
    )?;
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
