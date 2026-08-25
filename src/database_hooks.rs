use crate::{AuthError, AuthSession, AuthUser, OAuthAccount, VerificationValue};
use async_trait::async_trait;
use std::{collections::BTreeMap, future::Future};

/// Better Auth core database models that support schema fields and hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DatabaseModel {
    User,
    Session,
    Account,
    Verification,
}

impl DatabaseModel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Session => "session",
            Self::Account => "account",
            Self::Verification => "verification",
        }
    }
}

/// Typed record passed through Better Auth-compatible database hooks.
#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseRecord {
    User(AuthUser),
    Session(AuthSession),
    Account(OAuthAccount),
    Verification(VerificationValue),
}

impl DatabaseRecord {
    pub const fn model(&self) -> DatabaseModel {
        match self {
            Self::User(_) => DatabaseModel::User,
            Self::Session(_) => DatabaseModel::Session,
            Self::Account(_) => DatabaseModel::Account,
            Self::Verification(_) => DatabaseModel::Verification,
        }
    }
}

/// A request associated with a database hook. Native service calls have no
/// request, matching Better Auth's nullable endpoint context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseHookRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatabaseHookContext {
    pub request: Option<DatabaseHookRequest>,
    /// Internal-adapter creation source, such as Test Utils' `test` method.
    pub creation_method: Option<&'static str>,
}

impl DatabaseHookContext {
    /// Schedules non-authoritative work without delaying the database operation.
    /// Errors must be handled by the task because the write may already commit.
    pub fn run_in_background<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(future);
    }
}

/// Better Auth before-hook result: continue, replace/merge data, or return
/// `false` and cancel the database operation.
#[derive(Debug, Clone, PartialEq)]
pub enum BeforeDatabaseHook {
    Continue,
    Replace(Box<DatabaseRecord>),
    Cancel,
}

impl BeforeDatabaseHook {
    pub fn replace(record: DatabaseRecord) -> Self {
        Self::Replace(Box::new(record))
    }
}

#[async_trait]
pub trait DatabaseHooks: Send + Sync {
    async fn before_create(
        &self,
        _record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseHook, AuthError> {
        Ok(BeforeDatabaseHook::Continue)
    }

    async fn after_create(
        &self,
        _record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    async fn before_update(
        &self,
        _record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseHook, AuthError> {
        Ok(BeforeDatabaseHook::Continue)
    }

    async fn after_update(
        &self,
        _record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    async fn before_delete(
        &self,
        _record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<bool, AuthError> {
        Ok(true)
    }

    async fn after_delete(
        &self,
        _record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }
}

tokio::task_local! {
    static REQUEST_CONTEXT: DatabaseHookRequest;
    static CREATION_METHOD: &'static str;
}

pub(crate) fn current_context() -> DatabaseHookContext {
    DatabaseHookContext {
        request: REQUEST_CONTEXT.try_with(Clone::clone).ok(),
        creation_method: CREATION_METHOD.try_with(|method| *method).ok(),
    }
}

pub(crate) async fn scope_creation_method<F>(method: &'static str, future: F) -> F::Output
where
    F: Future,
{
    CREATION_METHOD.scope(method, future).await
}

#[cfg(feature = "axum")]
pub(crate) async fn scope_request<F>(request: DatabaseHookRequest, future: F) -> F::Output
where
    F: Future,
{
    REQUEST_CONTEXT.scope(request, future).await
}
