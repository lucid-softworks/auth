use super::{AuthStore, DatabaseCreate};
use crate::{AuthError, AuthSession, AuthUser, DatabaseModel, DatabaseRecord, OAuthAccount};
use async_trait::async_trait;
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

    async fn create(&self, operation: DatabaseCreateOperation)
    -> Result<DatabaseRecord, AuthError>;

    async fn update(&self, record: DatabaseRecord) -> Result<DatabaseRecord, AuthError>;

    async fn delete(
        &self,
        model: DatabaseModel,
        id: &str,
    ) -> Result<Option<DatabaseRecord>, AuthError>;
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
