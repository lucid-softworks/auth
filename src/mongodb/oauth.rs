use super::{MongoFilter, MongoFindOptions, MongoSort, MongoSortDirection, MongoStore, codec};
use crate::{
    AccountDeleteOutcome, AuthError, AuthUser, DatabaseWrite, DatabaseWriteOperation, OAuthAccount,
    OAuthAccountOwner, OAuthAccountStore, OAuthTokenUpdateOutcome,
    store::{
        DatabaseCreate, DependentAccountContext, DependentAccountPreparer, PreparedDatabaseId,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;

#[async_trait]
impl OAuthAccountStore for MongoStore {
    async fn find_oauth_account_owner(
        &self,
        issuer: &str,
        account_id: &str,
    ) -> Result<Option<OAuthAccountOwner>, AuthError> {
        let Some(account) =
            find_account(self, &[eq("issuer", issuer), eq("accountId", account_id)]).await?
        else {
            return Ok(None);
        };
        let user = super::user::find(self, "id", &account.user_id)
            .await?
            .ok_or_else(|| AuthError::Storage("OAuth account owner is missing".into()))?;
        Ok(Some(OAuthAccountOwner { account, user }))
    }

    async fn create_oauth_user(
        &self,
        user: DatabaseCreate<AuthUser>,
        preparer: &dyn DependentAccountPreparer,
    ) -> Result<OAuthAccountOwner, AuthError> {
        create_user(self, user, preparer).await
    }

    async fn link_oauth_account(
        &self,
        account: DatabaseCreate<OAuthAccount>,
    ) -> Result<OAuthAccount, AuthError> {
        if super::user::find(self, "id", &account.record.user_id)
            .await?
            .is_none()
        {
            return Err(AuthError::NotFound);
        }
        let (account, id) = account.into_parts(self)?;
        insert(self, account, id).await
    }

    async fn update_oauth_account_tokens(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError> {
        update(
            self,
            &account,
            &[
                eq("id", &account.id),
                eq("issuer", &account.issuer),
                eq("accountId", &account.account_id),
            ],
        )
        .await?
        .ok_or(AuthError::NotFound)
    }

    async fn list_user_accounts(&self, user_id: &str) -> Result<Vec<OAuthAccount>, AuthError> {
        self.find_records(
            "account",
            &[eq("userId", user_id)],
            &MongoFindOptions {
                sort: Some(MongoSort {
                    field: "createdAt".into(),
                    direction: MongoSortDirection::Ascending,
                }),
                ..MongoFindOptions::default()
            },
        )
        .await?
        .into_iter()
        .map(codec::decode_oauth)
        .collect()
    }

    async fn delete_user_account(
        &self,
        user_id: &str,
        account_id: &str,
        allow_last: bool,
    ) -> Result<AccountDeleteOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let filters = [eq("userId", user_id)];
        let accounts = super::query::execute::find_many(
            &mut transaction,
            schema,
            "account",
            &filters,
            &MongoFindOptions::default(),
        )
        .await?;
        let exists = accounts
            .iter()
            .any(|record| record.get("id") == Some(&json!(account_id)));
        if !exists {
            transaction.rollback().await.map_err(storage)?;
            return Ok(AccountDeleteOutcome::NotFound);
        }
        if accounts.len() == 1 && !allow_last {
            transaction.rollback().await.map_err(storage)?;
            return Ok(AccountDeleteOutcome::LastAccount);
        }
        super::query::execute::delete_many(
            &mut transaction,
            schema,
            "account",
            &[eq("id", account_id), eq("userId", user_id)],
        )
        .await?;
        transaction.commit().await.map_err(storage)?;
        Ok(AccountDeleteOutcome::Deleted)
    }

    async fn compare_and_swap_oauth_tokens(
        &self,
        account: OAuthAccount,
        expected_refresh_token: Option<&str>,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<OAuthTokenUpdateOutcome, AuthError> {
        let filters = [
            eq("id", &account.id),
            eq("userId", &account.user_id),
            MongoFilter::equal("refreshToken", json!(expected_refresh_token)),
            MongoFilter::equal("updatedAt", json!(expected_updated_at)),
        ];
        if let Some(updated) = update(self, &account, &filters).await? {
            return Ok(OAuthTokenUpdateOutcome::Updated(updated));
        }
        Ok(
            match find_account(
                self,
                &[eq("id", &account.id), eq("userId", &account.user_id)],
            )
            .await?
            {
                Some(current) => OAuthTokenUpdateOutcome::Stale(current),
                None => OAuthTokenUpdateOutcome::NotFound,
            },
        )
    }
}

pub(super) async fn create_user(
    store: &MongoStore,
    user: DatabaseCreate<AuthUser>,
    preparer: &dyn DependentAccountPreparer,
) -> Result<OAuthAccountOwner, AuthError> {
    let (mut user, user_id) = user.into_parts(store)?;
    user.email = user.email.to_lowercase();
    let schema = store.physical_schema()?;
    let mut transaction = store.begin().await?;
    let user_record = codec::create_record(store, "user", &user, &user_id)?;
    let user_record = super::query::execute::insert_required(&mut transaction, schema, "user", user_record)
        .await
        .map_err(user_error)?;
    let user = codec::decode("user", user_record)?;
    let account = preparer
        .prepare_account(DependentAccountContext {
            user: &user,
            user_operation: DatabaseWriteOperation::Create,
            existing_account: None,
        })
        .await?;
    let DatabaseWrite::Create(account) = account else {
        return Err(AuthError::Storage(
            "fresh OAuth user preparer returned an account update".into(),
        ));
    };
    let (mut account, id) = account.into_parts(store)?;
    account.user_id = user.id.clone();
    let account = insert_transaction(store, &mut transaction, schema, account, id).await?;
    transaction.commit().await.map_err(storage)?;
    Ok(OAuthAccountOwner { account, user })
}

pub(super) async fn insert(
    store: &MongoStore,
    account: OAuthAccount,
    id: PreparedDatabaseId,
) -> Result<OAuthAccount, AuthError> {
    let record = codec::oauth_create_record(store, &account, &id)?;
    codec::decode_oauth(store.insert_required_record("account", record).await?)
}

pub(super) async fn insert_transaction(
    store: &MongoStore,
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &super::schema::MongoSchema,
    account: OAuthAccount,
    id: PreparedDatabaseId,
) -> Result<OAuthAccount, AuthError> {
    let record = codec::oauth_create_record(store, &account, &id)?;
    codec::decode_oauth(
        super::query::execute::insert_required(transaction, schema, "account", record).await?,
    )
}

pub(super) async fn find_credential(
    store: &MongoStore,
    user_id: &str,
) -> Result<Option<OAuthAccount>, AuthError> {
    find_account(
        store,
        &[eq("userId", user_id), eq("providerId", "credential")],
    )
    .await
}

pub(super) async fn update(
    store: &MongoStore,
    account: &OAuthAccount,
    filters: &[MongoFilter],
) -> Result<Option<OAuthAccount>, AuthError> {
    let values = codec::oauth_update_record(store, account)?;
    store
        .update_record("account", filters, values)
        .await?
        .map(codec::decode_oauth)
        .transpose()
}

pub(super) async fn update_transaction(
    store: &MongoStore,
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &super::schema::MongoSchema,
    account: &OAuthAccount,
    filters: &[MongoFilter],
) -> Result<Option<OAuthAccount>, AuthError> {
    let values = codec::oauth_update_record(store, account)?;
    super::query::execute::update_one(transaction, schema, "account", filters, values)
        .await?
        .map(codec::decode_oauth)
        .transpose()
}

async fn find_account(
    store: &MongoStore,
    filters: &[MongoFilter],
) -> Result<Option<OAuthAccount>, AuthError> {
    store
        .find_record("account", filters, &[])
        .await?
        .map(codec::decode_oauth)
        .transpose()
}

fn eq(field: &str, value: &str) -> MongoFilter {
    MongoFilter::equal(field, json!(value))
}

fn user_error(error: AuthError) -> AuthError {
    match error {
        error if crate::mongodb::error::is_unique_violation(&error) => {
            AuthError::UserAlreadyExists
        }
        error => error,
    }
}

fn storage(error: AuthError) -> AuthError {
    AuthError::Storage(error.to_string())
}
