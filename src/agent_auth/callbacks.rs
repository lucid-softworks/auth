use super::{
    AgentApprovalMethod, AgentCapability, AgentCapabilityGrant, AgentCapabilityRequest, AgentHost,
    AgentIdentity, AgentMode,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fmt, sync::Arc};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentEndpointContext {
    pub method: String,
    pub path: String,
    pub base_url: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionUser {
    pub id: String,
    pub name: String,
    pub email: String,
    #[serde(flatten)]
    pub attributes: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionGrant {
    pub capability: String,
    pub constraints: Option<super::AgentCapabilityConstraints>,
    pub granted_by: Option<Uuid>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionIdentity {
    pub id: String,
    pub name: String,
    pub mode: AgentMode,
    pub capability_grants: Vec<AgentSessionGrant>,
    pub host_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub activated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionHost {
    pub id: String,
    pub user_id: Option<Uuid>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSession {
    pub r#type: AgentMode,
    pub agent_id: String,
    pub user_id: Option<Uuid>,
    pub agent: AgentSessionIdentity,
    pub host: Option<AgentSessionHost>,
    pub user: AgentSessionUser,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentHostSession {
    pub host: AgentHostSessionIdentity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentHostSessionIdentity {
    pub id: String,
    pub user_id: Option<Uuid>,
    pub default_capabilities: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct AgentApprovalMethodContext {
    pub user_id: Option<Uuid>,
    pub agent_name: String,
    pub host_id: Option<String>,
    pub capabilities: Vec<String>,
    pub preferred_method: Option<String>,
    pub supported_methods: Vec<AgentApprovalMethod>,
}

#[async_trait]
pub trait AgentApprovalMethodResolver: Send + Sync {
    async fn resolve(&self, context: AgentApprovalMethodContext) -> String;
}

#[async_trait]
pub trait AgentCapabilityValidator: Send + Sync {
    async fn validate(&self, capabilities: Vec<String>) -> bool;
}

#[derive(Debug, Clone)]
pub struct AgentFreshSessionWindowContext {
    pub endpoint: AgentEndpointContext,
    pub capabilities: Vec<String>,
}

#[async_trait]
pub trait AgentFreshSessionWindowResolver: Send + Sync {
    async fn resolve(&self, context: AgentFreshSessionWindowContext) -> u64;
}

#[async_trait]
pub trait AgentDynamicHostRegistrationResolver: Send + Sync {
    async fn allow(&self, context: AgentEndpointContext) -> bool;
}

#[derive(Debug, Clone)]
pub struct AgentDefaultHostCapabilitiesContext {
    pub endpoint: AgentEndpointContext,
    pub mode: AgentMode,
    pub user_id: Option<Uuid>,
    pub host_id: Option<String>,
    pub host_name: Option<String>,
}

#[async_trait]
pub trait AgentDefaultHostCapabilitiesResolver: Send + Sync {
    async fn resolve(&self, context: AgentDefaultHostCapabilitiesContext) -> Vec<String>;
}

#[derive(Debug, Clone)]
pub struct AgentAutonomousUserContext {
    pub endpoint: AgentEndpointContext,
    pub host_id: String,
    pub host_name: Option<String>,
    pub agent_id: String,
    pub agent_mode: AgentMode,
}

#[async_trait]
pub trait AgentAutonomousUserResolver: Send + Sync {
    async fn resolve(&self, context: AgentAutonomousUserContext) -> Option<AgentSessionUser>;
}

#[derive(Debug, Clone)]
pub struct AgentHostClaimedContext {
    pub endpoint: AgentEndpointContext,
    pub host_id: String,
    pub user_id: Uuid,
    pub previous_user_id: Option<Uuid>,
}

#[async_trait]
pub trait AgentHostClaimedCallback: Send + Sync {
    async fn call(&self, context: AgentHostClaimedContext);
}

#[derive(Debug, Clone)]
pub struct AgentGrantTtlContext {
    pub capability: String,
    pub agent_id: String,
    pub host_id: Option<String>,
    pub user_id: Option<Uuid>,
}

#[async_trait]
pub trait AgentGrantTtlResolver: Send + Sync {
    async fn resolve(&self, context: AgentGrantTtlContext) -> Option<u64>;
}

#[derive(Debug, Clone)]
pub struct AgentResolveCapabilitiesContext {
    pub capabilities: Vec<AgentCapability>,
    pub query: Option<String>,
    pub agent_session: Option<AgentSession>,
    pub host_session: Option<AgentHostSession>,
}

#[async_trait]
pub trait AgentCapabilitiesResolver: Send + Sync {
    async fn resolve(&self, context: AgentResolveCapabilitiesContext) -> Vec<AgentCapability>;
}

#[async_trait]
pub trait AgentCapabilityQueryResolver: Send + Sync {
    async fn resolve(
        &self,
        query: String,
        capabilities: Vec<AgentCapability>,
    ) -> Vec<AgentCapability>;
}

pub struct AgentStreamResult {
    pub body: mpsc::Receiver<Result<Vec<u8>, String>>,
    pub headers: BTreeMap<String, String>,
}

impl fmt::Debug for AgentStreamResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentStreamResult")
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum AgentExecuteResult {
    Data(Value),
    Async {
        status_url: String,
        retry_after: Option<u64>,
    },
    Stream(AgentStreamResult),
}

#[derive(Debug, thiserror::Error)]
pub enum AgentExecuteError {
    #[error("{0}")]
    Internal(String),
    #[error("{message}")]
    Api {
        message: String,
        error: super::AgentAuthApiError,
    },
}

impl AgentExecuteError {
    pub fn api(error: super::AgentAuthApiError) -> Self {
        Self::Api {
            message: error.message.clone(),
            error,
        }
    }
}

impl From<String> for AgentExecuteError {
    fn from(error: String) -> Self {
        Self::Internal(error)
    }
}

impl From<super::AgentAuthApiError> for AgentExecuteError {
    fn from(error: super::AgentAuthApiError) -> Self {
        Self::api(error)
    }
}

#[derive(Clone)]
pub struct AgentGrantRevoker {
    store: Arc<dyn super::AgentAuthStore>,
    grant_id: String,
}

impl AgentGrantRevoker {
    #[cfg(any(feature = "axum", test))]
    pub(crate) fn new(store: Arc<dyn super::AgentAuthStore>, grant_id: String) -> Self {
        Self { store, grant_id }
    }

    /// Marks the grant which authorized an execution as consumed.
    pub async fn revoke(&self) -> Result<(), crate::AuthError> {
        self.store
            .consume_grant(&self.grant_id, chrono::Utc::now())
            .await?;
        Ok(())
    }
}

impl fmt::Debug for AgentGrantRevoker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentGrantRevoker")
            .field("grant_id", &self.grant_id)
            .finish_non_exhaustive()
    }
}

pub struct AgentExecuteContext {
    pub endpoint: AgentEndpointContext,
    pub capability: String,
    pub capability_definition: AgentCapability,
    pub arguments: Option<Map<String, Value>>,
    pub agent_session: AgentSession,
    pub grant: AgentCapabilityGrant,
    pub revoke_grant: AgentGrantRevoker,
}

impl fmt::Debug for AgentExecuteContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentExecuteContext")
            .field("capability", &self.capability)
            .field("agent_session", &self.agent_session)
            .field("grant", &self.grant)
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait AgentExecuteHandler: Send + Sync {
    async fn execute(
        &self,
        context: AgentExecuteContext,
    ) -> Result<AgentExecuteResult, AgentExecuteError>;
}

#[derive(Debug, Clone)]
pub struct AgentAutonomousClaimedContext {
    pub endpoint: AgentEndpointContext,
    pub agent: AgentIdentity,
    pub host: AgentHost,
    pub user_id: Uuid,
    pub capabilities: Vec<String>,
}

#[async_trait]
pub trait AgentAutonomousClaimedCallback: Send + Sync {
    async fn call(&self, context: AgentAutonomousClaimedContext);
}

pub fn normalize_capability_requests(
    requests: &[AgentCapabilityRequest],
) -> Vec<(String, Option<super::AgentCapabilityConstraints>)> {
    requests
        .iter()
        .map(|request| (request.name().to_owned(), request.constraints().cloned()))
        .collect()
}
