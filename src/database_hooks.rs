use crate::{AuthError, AuthSession, AuthUser, OAuthAccount, VerificationValue};
use async_trait::async_trait;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

/// Better Auth core database models that support schema fields and hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DatabaseModel {
    User,
    Session,
    Account,
    Verification,
    Organization,
}

impl DatabaseModel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Session => "session",
            Self::Account => "account",
            Self::Verification => "verification",
            Self::Organization => "organization",
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

/// Response changes produced by work deferred until an HTTP request has
/// finished its database operations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeferredHookResponse {
    headers: Vec<(String, String)>,
}

impl DeferredHookResponse {
    /// Appends one response header after the deferred work succeeds.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    #[cfg(feature = "axum")]
    pub(crate) fn into_headers(self) -> Vec<(String, String)> {
        self.headers
    }
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

    /// Queues authoritative post-write work until the surrounding HTTP
    /// request has completed all of its database operations.
    ///
    /// The future is returned unchanged when no Axum request queue is active,
    /// allowing native callers to choose whether to run it immediately.
    pub fn try_defer_after_commit<F>(&self, future: F) -> Result<(), F>
    where
        F: Future<Output = Result<DeferredHookResponse, AuthError>> + Send + 'static,
    {
        let mut future = Some(future);
        let queued = DEFERRED_AFTER_COMMIT.try_with(|queue| {
            queue.push(Box::pin(
                future.take().expect("deferred future is available"),
            ));
        });
        match queued {
            Ok(()) => Ok(()),
            Err(_) => Err(future.expect("deferred future was not queued")),
        }
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
    static DEFERRED_AFTER_COMMIT: DeferredHookQueue;
}

type DeferredHookFuture =
    Pin<Box<dyn Future<Output = Result<DeferredHookResponse, AuthError>> + Send + 'static>>;

#[derive(Clone, Default)]
pub(crate) struct DeferredHookQueue(Arc<Mutex<VecDeque<DeferredHookFuture>>>);

impl DeferredHookQueue {
    fn push(&self, future: DeferredHookFuture) {
        self.0
            .lock()
            .expect("deferred hook queue lock is not poisoned")
            .push_back(future);
    }

    #[cfg(feature = "axum")]
    pub(crate) fn pop(&self) -> Option<DeferredHookFuture> {
        self.0
            .lock()
            .expect("deferred hook queue lock is not poisoned")
            .pop_front()
    }
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
pub(crate) async fn scope_request<F>(
    request: DatabaseHookRequest,
    queue: DeferredHookQueue,
    future: F,
) -> F::Output
where
    F: Future,
{
    REQUEST_CONTEXT
        .scope(request, DEFERRED_AFTER_COMMIT.scope(queue, future))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn unavailable_request_queue_returns_the_unpolled_future() {
        let polled = Arc::new(AtomicBool::new(false));
        let future_polled = polled.clone();
        let future = DatabaseHookContext::default()
            .try_defer_after_commit(async move {
                future_polled.store(true, Ordering::SeqCst);
                Ok(DeferredHookResponse::default())
            })
            .expect_err("no request queue");

        assert!(!polled.load(Ordering::SeqCst));
        future.await.unwrap();
        assert!(polled.load(Ordering::SeqCst));
    }
}
