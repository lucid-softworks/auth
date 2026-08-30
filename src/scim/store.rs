use super::{ScimGroup, ScimManagedConnection, ScimManagedConnectionEvent, ScimManagedCredential, ScimUser};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimConnectionBinding {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub decommissioned_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredScimUser {
    pub resource: ScimUser,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub user_id: String,
    pub profile_managed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredScimGroup {
    pub resource: ScimGroup,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScimStoreError {
    #[error("resource not found")]
    NotFound,
    #[error("userName must be unique within a connection")]
    DuplicateUserName,
    #[error("externalId must be unique within a connection")]
    DuplicateExternalId,
    #[error("displayName must be unique within a connection")]
    DuplicateDisplayName,
    #[error("a Group member does not identify an active same-connection SCIM User")]
    InvalidMember,
    #[error("the connection provisioningDomainId changed after first use")]
    BindingConflict,
    #[error("the SCIM connection is decommissioned")]
    Decommissioned,
    #[error("another SCIM source already manages this User profile")]
    ProfileConflict,
    #[error("the SCIM resource changed concurrently; retry the request")]
    ConcurrentMutation,
    #[error("the managed creation request id has already been used")]
    CreationRequestConflict,
    #[error("the maximum active managed credential count has been reached")]
    CredentialLimit,
    #[error("managed credential not found")]
    CredentialNotFound,
    #[error("SCIM storage failed: {0}")]
    Storage(String),
}

#[async_trait]
pub trait ScimStore: Send + Sync {
    /// Returns the shared Better Auth adapter when this store persists through
    /// the native logical-row transaction boundary.
    fn backing_auth_store(&self) -> Option<std::sync::Arc<dyn crate::AuthStore>> {
        None
    }

    async fn bind_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ScimConnectionBinding, ScimStoreError>;

    async fn create_user(&self, user: StoredScimUser) -> Result<StoredScimUser, ScimStoreError>;
    async fn find_user(
        &self,
        connection_id: &str,
        resource_id: &str,
    ) -> Result<Option<StoredScimUser>, ScimStoreError>;
    async fn list_users(&self, connection_id: &str) -> Result<Vec<StoredScimUser>, ScimStoreError>;
    async fn replace_user(
        &self,
        connection_id: &str,
        resource_id: &str,
        resource: ScimUser,
        now: DateTime<Utc>,
    ) -> Result<StoredScimUser, ScimStoreError>;
    async fn delete_user(
        &self,
        connection_id: &str,
        resource_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<StoredScimUser>, ScimStoreError>;

    async fn create_group(
        &self,
        group: StoredScimGroup,
    ) -> Result<StoredScimGroup, ScimStoreError>;
    async fn find_group(
        &self,
        connection_id: &str,
        resource_id: &str,
    ) -> Result<Option<StoredScimGroup>, ScimStoreError>;
    async fn list_groups(
        &self,
        connection_id: &str,
    ) -> Result<Vec<StoredScimGroup>, ScimStoreError>;
    async fn replace_group(
        &self,
        connection_id: &str,
        resource_id: &str,
        resource: ScimGroup,
        now: DateTime<Utc>,
    ) -> Result<StoredScimGroup, ScimStoreError>;
    async fn delete_group(
        &self,
        connection_id: &str,
        resource_id: &str,
    ) -> Result<Option<StoredScimGroup>, ScimStoreError>;

    async fn create_managed_connection(
        &self,
        creation_request_id: &str,
        connection: ScimManagedConnection,
        credential: ScimManagedCredential,
        events: Vec<ScimManagedConnectionEvent>,
    ) -> Result<(ScimManagedConnection, ScimManagedCredential), ScimStoreError>;
    async fn list_managed_connections(
        &self,
        provisioning_domain_id: &str,
    ) -> Result<Vec<ScimManagedConnection>, ScimStoreError>;
    async fn find_managed_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
    ) -> Result<Option<ScimManagedConnection>, ScimStoreError>;
    async fn list_managed_credentials(
        &self,
        connection_record_id: &str,
    ) -> Result<Vec<ScimManagedCredential>, ScimStoreError>;
    async fn find_managed_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<(ScimManagedConnection, ScimManagedCredential)>, ScimStoreError>;
    async fn rotate_managed_credential(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        credential: ScimManagedCredential,
        event: ScimManagedConnectionEvent,
        max_active_credentials: usize,
        now: DateTime<Utc>,
    ) -> Result<(ScimManagedConnection, ScimManagedCredential), ScimStoreError>;
    async fn revoke_managed_credential(
        &self,
        connection_record_id: &str,
        credential_id: &str,
        actor_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ScimManagedCredential, ScimStoreError>;
    async fn touch_managed_credential(
        &self,
        credential_id: &str,
        now: DateTime<Utc>,
        minimum_interval_seconds: u64,
    ) -> Result<(), ScimStoreError>;
    async fn list_managed_events(
        &self,
        connection_record_id: &str,
    ) -> Result<Vec<ScimManagedConnectionEvent>, ScimStoreError>;
    async fn decommission_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        actor_id: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, ScimStoreError>;
    async fn decommission_managed_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        actor_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ScimManagedConnection, ScimStoreError>;
}
