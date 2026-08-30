use super::{
    ScimConnectionBinding, ScimManagedConnection, ScimManagedConnectionEvent,
    ScimManagedCredential, ScimStore, ScimStoreError,
    store::{StoredScimGroup, StoredScimUser},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;

mod codec;
mod core;
pub(super) mod decommission;
pub(super) mod keys;
mod managed;

/// SCIM persistence backed by the application's native Better Auth adapter.
#[derive(Clone)]
pub struct DatabaseScimStore {
    pub(super) store: Arc<dyn crate::AuthStore>,
}

impl DatabaseScimStore {
    pub fn new(store: Arc<dyn crate::AuthStore>) -> Self {
        Self { store }
    }
}

impl std::fmt::Debug for DatabaseScimStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseScimStore")
            .field("adapter", &self.store.database_adapter_name())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ScimStore for DatabaseScimStore {
    fn backing_auth_store(&self) -> Option<Arc<dyn crate::AuthStore>> {
        Some(self.store.clone())
    }

    async fn bind_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ScimConnectionBinding, ScimStoreError> {
        core::bind_connection(self, connection_id, provisioning_domain_id, now).await
    }

    async fn create_user(&self, user: StoredScimUser) -> Result<StoredScimUser, ScimStoreError> {
        core::create_user(self, user).await
    }

    async fn find_user(
        &self,
        connection_id: &str,
        resource_id: &str,
    ) -> Result<Option<StoredScimUser>, ScimStoreError> {
        core::find_user(self, connection_id, resource_id).await
    }

    async fn list_users(
        &self,
        connection_id: &str,
    ) -> Result<Vec<StoredScimUser>, ScimStoreError> {
        core::list_users(self, connection_id).await
    }

    async fn replace_user(
        &self,
        connection_id: &str,
        resource_id: &str,
        resource: super::ScimUser,
        now: DateTime<Utc>,
    ) -> Result<StoredScimUser, ScimStoreError> {
        core::replace_user(self, connection_id, resource_id, resource, now).await
    }

    async fn delete_user(
        &self,
        connection_id: &str,
        resource_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<StoredScimUser>, ScimStoreError> {
        core::delete_user(self, connection_id, resource_id, now).await
    }

    async fn create_group(
        &self,
        group: StoredScimGroup,
    ) -> Result<StoredScimGroup, ScimStoreError> {
        core::create_group(self, group).await
    }

    async fn find_group(
        &self,
        connection_id: &str,
        resource_id: &str,
    ) -> Result<Option<StoredScimGroup>, ScimStoreError> {
        core::find_group(self, connection_id, resource_id).await
    }

    async fn list_groups(
        &self,
        connection_id: &str,
    ) -> Result<Vec<StoredScimGroup>, ScimStoreError> {
        core::list_groups(self, connection_id).await
    }

    async fn replace_group(
        &self,
        connection_id: &str,
        resource_id: &str,
        resource: super::ScimGroup,
        now: DateTime<Utc>,
    ) -> Result<StoredScimGroup, ScimStoreError> {
        core::replace_group(self, connection_id, resource_id, resource, now).await
    }

    async fn delete_group(
        &self,
        connection_id: &str,
        resource_id: &str,
    ) -> Result<Option<StoredScimGroup>, ScimStoreError> {
        core::delete_group(self, connection_id, resource_id).await
    }

    async fn create_managed_connection(
        &self,
        creation_request_id: &str,
        connection: ScimManagedConnection,
        credential: ScimManagedCredential,
        events: Vec<ScimManagedConnectionEvent>,
    ) -> Result<(ScimManagedConnection, ScimManagedCredential), ScimStoreError> {
        managed::create_connection(self, creation_request_id, connection, credential, events).await
    }

    async fn list_managed_connections(
        &self,
        provisioning_domain_id: &str,
    ) -> Result<Vec<ScimManagedConnection>, ScimStoreError> {
        managed::list_connections(self, provisioning_domain_id).await
    }

    async fn find_managed_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
    ) -> Result<Option<ScimManagedConnection>, ScimStoreError> {
        managed::find_connection(self, connection_id, provisioning_domain_id).await
    }

    async fn list_managed_credentials(
        &self,
        connection_record_id: &str,
    ) -> Result<Vec<ScimManagedCredential>, ScimStoreError> {
        managed::list_credentials(self, connection_record_id).await
    }

    async fn find_managed_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<(ScimManagedConnection, ScimManagedCredential)>, ScimStoreError> {
        managed::find_credential(self, credential_id).await
    }

    async fn rotate_managed_credential(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        credential: ScimManagedCredential,
        event: ScimManagedConnectionEvent,
        max_active_credentials: usize,
        now: DateTime<Utc>,
    ) -> Result<(ScimManagedConnection, ScimManagedCredential), ScimStoreError> {
        managed::rotate_credential(
            self,
            connection_id,
            provisioning_domain_id,
            credential,
            event,
            max_active_credentials,
            now,
        )
        .await
    }

    async fn revoke_managed_credential(
        &self,
        connection_record_id: &str,
        credential_id: &str,
        actor_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ScimManagedCredential, ScimStoreError> {
        managed::revoke_credential(self, connection_record_id, credential_id, actor_id, now).await
    }

    async fn touch_managed_credential(
        &self,
        credential_id: &str,
        now: DateTime<Utc>,
        minimum_interval_seconds: u64,
    ) -> Result<(), ScimStoreError> {
        managed::touch_credential(self, credential_id, now, minimum_interval_seconds).await
    }

    async fn list_managed_events(
        &self,
        connection_record_id: &str,
    ) -> Result<Vec<ScimManagedConnectionEvent>, ScimStoreError> {
        managed::list_events(self, connection_record_id).await
    }

    async fn decommission_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        _actor_id: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, ScimStoreError> {
        decommission::run(
            self.store.clone(),
            Arc::new(super::ScimOptions::default()),
            connection_id,
            provisioning_domain_id,
            now,
        )
        .await
        .map_err(|error| ScimStoreError::Storage(error.to_string()))
    }

    async fn decommission_managed_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        actor_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ScimManagedConnection, ScimStoreError> {
        managed::decommission(self, connection_id, provisioning_domain_id, actor_id, now).await
    }
}
