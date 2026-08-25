use crate::{AuthUser, DatabaseHookRequest};
use async_trait::async_trait;
use serde::Serialize;
use std::{fmt, future::Future};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DubLead {
    pub click_id: String,
    pub event_name: String,
    pub customer_external_id: String,
    pub customer_name: String,
    pub customer_email: String,
    pub customer_avatar: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DubLeadError {
    message: String,
}

impl DubLeadError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DubCustomLeadError {
    message: String,
}

impl DubCustomLeadError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait DubLeadTracker: Send + Sync {
    async fn track_lead(&self, lead: &DubLead) -> Result<(), DubLeadError>;
}

#[async_trait]
pub trait DubCustomLeadTrack: Send + Sync {
    async fn track(
        &self,
        user: &AuthUser,
        request: &DatabaseHookRequest,
    ) -> Result<(), DubCustomLeadError>;
}

pub struct FnDubLeadTracker<F>(F);

impl<F> FnDubLeadTracker<F> {
    pub fn new(callback: F) -> Self {
        Self(callback)
    }
}

impl<F> fmt::Debug for FnDubLeadTracker<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FnDubLeadTracker(..)")
    }
}

#[async_trait]
impl<F, Fut> DubLeadTracker for FnDubLeadTracker<F>
where
    F: Fn(DubLead) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), DubLeadError>> + Send,
{
    async fn track_lead(&self, lead: &DubLead) -> Result<(), DubLeadError> {
        (self.0)(lead.clone()).await
    }
}

pub struct FnDubCustomLeadTrack<F>(F);

impl<F> FnDubCustomLeadTrack<F> {
    pub fn new(callback: F) -> Self {
        Self(callback)
    }
}

impl<F> fmt::Debug for FnDubCustomLeadTrack<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FnDubCustomLeadTrack(..)")
    }
}

#[async_trait]
impl<F, Fut> DubCustomLeadTrack for FnDubCustomLeadTrack<F>
where
    F: Fn(AuthUser, DatabaseHookRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), DubCustomLeadError>> + Send,
{
    async fn track(
        &self,
        user: &AuthUser,
        request: &DatabaseHookRequest,
    ) -> Result<(), DubCustomLeadError> {
        (self.0)(user.clone(), request.clone()).await
    }
}
