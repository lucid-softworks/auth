use super::{AutumnIdentity, AutumnIdentityError};
use crate::{Organization, SessionWithUser};
use async_trait::async_trait;
use std::{fmt, future::Future};

#[async_trait]
pub trait AutumnIdentityProvider: Send + Sync {
    async fn identify(
        &self,
        session: Option<&SessionWithUser>,
        organization: Option<&Organization>,
    ) -> Result<Option<AutumnIdentity>, AutumnIdentityError>;
}

pub struct FnAutumnIdentityProvider<F>(F);

impl<F> FnAutumnIdentityProvider<F> {
    pub fn new(callback: F) -> Self {
        Self(callback)
    }
}

pub struct SyncAutumnIdentityProvider<F>(F);

impl<F> SyncAutumnIdentityProvider<F> {
    pub fn new(callback: F) -> Self {
        Self(callback)
    }
}

impl<F> fmt::Debug for SyncAutumnIdentityProvider<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SyncAutumnIdentityProvider(..)")
    }
}

impl<F> fmt::Debug for FnAutumnIdentityProvider<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FnAutumnIdentityProvider(..)")
    }
}

#[async_trait]
impl<F, Fut> AutumnIdentityProvider for FnAutumnIdentityProvider<F>
where
    F: Fn(Option<SessionWithUser>, Option<Organization>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Option<AutumnIdentity>, AutumnIdentityError>> + Send,
{
    async fn identify(
        &self,
        session: Option<&SessionWithUser>,
        organization: Option<&Organization>,
    ) -> Result<Option<AutumnIdentity>, AutumnIdentityError> {
        (self.0)(session.cloned(), organization.cloned()).await
    }
}

#[async_trait]
impl<F> AutumnIdentityProvider for SyncAutumnIdentityProvider<F>
where
    F: Fn(
            Option<SessionWithUser>,
            Option<Organization>,
        ) -> Result<Option<AutumnIdentity>, AutumnIdentityError>
        + Send
        + Sync,
{
    async fn identify(
        &self,
        session: Option<&SessionWithUser>,
        organization: Option<&Organization>,
    ) -> Result<Option<AutumnIdentity>, AutumnIdentityError> {
        (self.0)(session.cloned(), organization.cloned())
    }
}
