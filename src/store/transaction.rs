use super::{AuthStore, DatabaseCreate};
use crate::{
    AuthError, AuthSession, AuthUser, DashAdapterSort, DashAdapterWhere, DatabaseModel,
    DatabaseRecord, OAuthAccount,
};
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::{any::Any, future::Future, pin::Pin, sync::Arc};

/// One typed logical create executed by an active database transaction.
#[derive(Debug)]
pub enum DatabaseCreateOperation {
    User(DatabaseCreate<AuthUser>),
    Session(DatabaseCreate<AuthSession>),
    Account(DatabaseCreate<OAuthAccount>),
    Verification(DatabaseCreate<crate::VerificationValue>),
}

impl DatabaseCreateOperation {
    pub const fn model(&self) -> DatabaseModel {
        match self {
            Self::User(_) => DatabaseModel::User,
            Self::Session(_) => DatabaseModel::Session,
            Self::Account(_) => DatabaseModel::Account,
            Self::Verification(_) => DatabaseModel::Verification,
        }
    }
}

/// The generic Better Auth row boundary visible to reentrant hooks.
///
/// Values always use canonical logical model fields. Concrete adapters own
/// physical schema mapping and must return the actual persisted record.
#[async_trait]
pub trait DatabaseTransaction: Send + Sync {
    async fn find_by_id(
        &self,
        model: DatabaseModel,
        id: &str,
    ) -> Result<Option<DatabaseRecord>, AuthError>;

    async fn find_oauth_account_owner(
        &self,
        issuer: &str,
        account_id: &str,
    ) -> Result<Option<crate::OAuthAccountOwner>, AuthError> {
        let equal = |field: &str, value: &str| DashAdapterWhere {
            field: field.into(),
            value: Value::String(value.into()),
            operator: crate::DashAdapterOperator::Eq,
            connector: None,
        };
        let Some(account) = self
            .find_records(
                "account",
                &[equal("issuer", issuer), equal("accountId", account_id)],
                Some(1),
                0,
                None,
                &[],
            )
            .await?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let account: OAuthAccount = serde_json::from_value(Value::Object(account))
            .map_err(|error| AuthError::Storage(format!("invalid transaction account row: {error}")))?;
        let Some(DatabaseRecord::User(user)) = self
            .find_by_id(DatabaseModel::User, &account.user_id)
            .await?
        else {
            return Err(AuthError::Storage("OAuth account owner is missing".into()));
        };
        Ok(Some(crate::OAuthAccountOwner { account, user }))
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError> {
        let filter = DashAdapterWhere {
            field: "email".into(),
            value: Value::String(email.to_lowercase()),
            operator: crate::DashAdapterOperator::Eq,
            connector: None,
        };
        let Some(user) = self
            .find_records("user", &[filter], Some(1), 0, None, &["id".into()])
            .await?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let id = user
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Storage("transaction user row has no id".into()))?;
        match self.find_by_id(DatabaseModel::User, id).await? {
            Some(DatabaseRecord::User(user)) => Ok(Some(user)),
            Some(_) => unreachable!("transaction lookup preserves its model"),
            None => Ok(None),
        }
    }

    async fn create(&self, operation: DatabaseCreateOperation)
    -> Result<DatabaseRecord, AuthError>;

    async fn update(&self, record: DatabaseRecord) -> Result<DatabaseRecord, AuthError>;

    async fn delete(
        &self,
        model: DatabaseModel,
        id: &str,
    ) -> Result<Option<DatabaseRecord>, AuthError>;

    /// Finds canonical logical rows, including plugin-owned models, inside
    /// the active adapter transaction.
    async fn find_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&DashAdapterSort>,
        select: &[String],
    ) -> Result<Vec<Map<String, Value>>, AuthError>;

    /// Creates one canonical logical row inside the active transaction.
    async fn create_record(
        &self,
        model: &str,
        data: Map<String, Value>,
    ) -> Result<Map<String, Value>, AuthError>;

    /// Updates and returns the first canonical logical row matching a filter.
    async fn update_record(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        update: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError>;

    /// Deletes every canonical logical row matching a filter.
    async fn delete_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
    ) -> Result<u64, AuthError>;

    /// Counts canonical logical rows matching a filter.
    async fn count_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
    ) -> Result<u64, AuthError>;

    /// Atomically increments numeric fields, applies set fields, and returns
    /// the first canonical logical row matching a revision fence.
    async fn increment_record(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        increments: Map<String, Value>,
        set: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError>;
}

/// Object-safe transaction callback implemented by downstream adapters and
/// erased by [`run_database_transaction`] for typed service callers.
#[async_trait]
pub trait DatabaseTransactionOperation: Send {
    async fn execute(
        self: Box<Self>,
        transaction: Arc<dyn DatabaseTransaction>,
    ) -> Result<Box<dyn Any + Send>, AuthError>;
}

pub type DatabaseTransactionFuture<T> =
    Pin<Box<dyn Future<Output = Result<T, AuthError>> + Send + 'static>>;

struct TypedOperation<F>(F);

#[async_trait]
impl<T, F> DatabaseTransactionOperation for TypedOperation<F>
where
    T: Send + 'static,
    F: FnOnce(Arc<dyn DatabaseTransaction>) -> DatabaseTransactionFuture<T> + Send + 'static,
{
    async fn execute(
        self: Box<Self>,
        transaction: Arc<dyn DatabaseTransaction>,
    ) -> Result<Box<dyn Any + Send>, AuthError> {
        let value = (self.0)(transaction).await?;
        Ok(Box::new(value))
    }
}

/// Runs a typed, non-retrying operation through an adapter's public
/// transaction boundary.
pub async fn run_database_transaction<T, F>(
    store: &dyn AuthStore,
    operation: F,
) -> Result<T, AuthError>
where
    T: Send + 'static,
    F: FnOnce(Arc<dyn DatabaseTransaction>) -> DatabaseTransactionFuture<T> + Send + 'static,
{
    if let Some(transaction) = crate::database_hooks::current_transaction() {
        let value = Box::new(TypedOperation(operation))
            .execute(transaction)
            .await?;
        return downcast_transaction_result(value);
    }
    let value = store
        .transaction(Box::new(TypedOperation(operation)))
        .await?;
    downcast_transaction_result(value)
}

fn downcast_transaction_result<T: Send + 'static>(
    value: Box<dyn Any + Send>,
) -> Result<T, AuthError> {
    value.downcast::<T>().map(|value| *value).map_err(|_| {
        AuthError::Storage("database transaction returned an incompatible result".into())
    })
}
