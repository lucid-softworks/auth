use super::{
    ScimConnectionBinding, ScimManagedConnection, ScimManagedConnectionEvent,
    ScimManagedCredential, ScimStore, ScimStoreError,
    store::{StoredScimGroup, StoredScimUser},
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::Mutex;

mod state;
use state::{
    MemoryScimState, decommission, ensure_active_binding, ensure_group_members, ensure_group_unique,
    ensure_user_unique,
};

#[derive(Default)]
pub struct MemoryScimStore {
    state: Mutex<MemoryScimState>,
}

impl std::fmt::Debug for MemoryScimStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MemoryScimStore(..)")
    }
}

impl MemoryScimStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ScimStore for MemoryScimStore {
    async fn bind_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        _now: DateTime<Utc>,
    ) -> Result<ScimConnectionBinding, ScimStoreError> {
        let mut state = self.state.lock().await;
        if let Some(binding) = state.bindings.get(connection_id) {
            if binding.provisioning_domain_id != provisioning_domain_id {
                return Err(ScimStoreError::BindingConflict);
            }
            if binding.decommissioned_at.is_some() {
                return Err(ScimStoreError::Decommissioned);
            }
            return Ok(binding.clone());
        }
        let binding = ScimConnectionBinding {
            connection_id: connection_id.into(),
            provisioning_domain_id: provisioning_domain_id.into(),
            decommissioned_at: None,
        };
        state.bindings.insert(connection_id.into(), binding.clone());
        Ok(binding)
    }

    async fn create_user(&self, user: StoredScimUser) -> Result<StoredScimUser, ScimStoreError> {
        let mut state = self.state.lock().await;
        ensure_user_unique(&state, &user, None)?;
        ensure_active_binding(&state, &user.connection_id)?;
        let id = user.resource.id.clone().expect("stored SCIM users have ids");
        state.users.insert(id, user.clone());
        Ok(user)
    }

    async fn find_user(
        &self,
        connection_id: &str,
        resource_id: &str,
    ) -> Result<Option<StoredScimUser>, ScimStoreError> {
        let state = self.state.lock().await;
        Ok(state
            .users
            .get(resource_id)
            .filter(|user| user.connection_id == connection_id)
            .cloned())
    }

    async fn list_users(&self, connection_id: &str) -> Result<Vec<StoredScimUser>, ScimStoreError> {
        let state = self.state.lock().await;
        let mut users = state
            .users
            .values()
            .filter(|user| user.connection_id == connection_id)
            .cloned()
            .collect::<Vec<_>>();
        users.sort_by_key(|user| (user.created_at, user.resource.id.clone()));
        Ok(users)
    }

    async fn replace_user(
        &self,
        connection_id: &str,
        resource_id: &str,
        resource: super::ScimUser,
        now: DateTime<Utc>,
    ) -> Result<StoredScimUser, ScimStoreError> {
        let mut state = self.state.lock().await;
        let Some(existing) = state
            .users
            .get(resource_id)
            .filter(|user| user.connection_id == connection_id)
            .cloned()
        else {
            return Err(ScimStoreError::NotFound);
        };
        let candidate = StoredScimUser {
            resource,
            updated_at: now,
            ..existing
        };
        ensure_user_unique(&state, &candidate, Some(resource_id))?;
        ensure_active_binding(&state, connection_id)?;
        state.users.insert(resource_id.into(), candidate.clone());
        Ok(candidate)
    }

    async fn delete_user(
        &self,
        connection_id: &str,
        resource_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<StoredScimUser>, ScimStoreError> {
        let mut state = self.state.lock().await;
        let Some(user) = state
            .users
            .get(resource_id)
            .filter(|user| user.connection_id == connection_id)
            .cloned()
        else {
            return Ok(None);
        };
        state.users.remove(resource_id);
        for group in state.groups.values_mut() {
            group.resource.members.retain(|member| member.value != resource_id);
            group.updated_at = now;
        }
        if let Some(external_id) = &user.resource.external_id {
            state.tombstones.insert(
                (connection_id.into(), external_id.clone()),
                (user.user_id.clone(), if user.profile_managed { "manage" } else { "preserve" }.into()),
            );
        }
        Ok(Some(user))
    }

    async fn create_group(
        &self,
        group: StoredScimGroup,
    ) -> Result<StoredScimGroup, ScimStoreError> {
        let mut state = self.state.lock().await;
        ensure_group_unique(&state, &group, None)?;
        ensure_group_members(&state, &group)?;
        ensure_active_binding(&state, &group.connection_id)?;
        let id = group.resource.id.clone().expect("stored SCIM groups have ids");
        state.groups.insert(id, group.clone());
        Ok(group)
    }

    async fn find_group(
        &self,
        connection_id: &str,
        resource_id: &str,
    ) -> Result<Option<StoredScimGroup>, ScimStoreError> {
        let state = self.state.lock().await;
        Ok(state
            .groups
            .get(resource_id)
            .filter(|group| group.connection_id == connection_id)
            .cloned())
    }

    async fn list_groups(
        &self,
        connection_id: &str,
    ) -> Result<Vec<StoredScimGroup>, ScimStoreError> {
        let state = self.state.lock().await;
        let mut groups = state
            .groups
            .values()
            .filter(|group| group.connection_id == connection_id)
            .cloned()
            .collect::<Vec<_>>();
        groups.sort_by_key(|group| (group.created_at, group.resource.id.clone()));
        Ok(groups)
    }

    async fn replace_group(
        &self,
        connection_id: &str,
        resource_id: &str,
        resource: super::ScimGroup,
        now: DateTime<Utc>,
    ) -> Result<StoredScimGroup, ScimStoreError> {
        let mut state = self.state.lock().await;
        let Some(existing) = state
            .groups
            .get(resource_id)
            .filter(|group| group.connection_id == connection_id)
            .cloned()
        else {
            return Err(ScimStoreError::NotFound);
        };
        let candidate = StoredScimGroup {
            resource,
            updated_at: now,
            ..existing
        };
        ensure_group_unique(&state, &candidate, Some(resource_id))?;
        ensure_group_members(&state, &candidate)?;
        ensure_active_binding(&state, connection_id)?;
        state.groups.insert(resource_id.into(), candidate.clone());
        Ok(candidate)
    }

    async fn delete_group(
        &self,
        connection_id: &str,
        resource_id: &str,
    ) -> Result<Option<StoredScimGroup>, ScimStoreError> {
        let mut state = self.state.lock().await;
        if state
            .groups
            .get(resource_id)
            .is_some_and(|group| group.connection_id == connection_id)
        {
            Ok(state.groups.remove(resource_id))
        } else {
            Ok(None)
        }
    }

    async fn create_managed_connection(
        &self,
        creation_request_id: &str,
        connection: ScimManagedConnection,
        credential: ScimManagedCredential,
        event: ScimManagedConnectionEvent,
    ) -> Result<(ScimManagedConnection, ScimManagedCredential), ScimStoreError> {
        let mut state = self.state.lock().await;
        if !state.creation_requests.insert(creation_request_id.into()) {
            return Err(ScimStoreError::CreationRequestConflict);
        }
        state
            .managed_connections
            .insert(connection.connection_id.clone(), connection.clone());
        state
            .managed_credentials
            .insert(credential.credential_id.clone(), credential.clone());
        state.managed_events.push(event);
        Ok((connection, credential))
    }

    async fn list_managed_connections(
        &self,
        provisioning_domain_id: &str,
    ) -> Result<Vec<ScimManagedConnection>, ScimStoreError> {
        let state = self.state.lock().await;
        Ok(state
            .managed_connections
            .values()
            .filter(|connection| connection.provisioning_domain_id == provisioning_domain_id)
            .cloned()
            .collect())
    }

    async fn find_managed_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
    ) -> Result<Option<ScimManagedConnection>, ScimStoreError> {
        let state = self.state.lock().await;
        Ok(state
            .managed_connections
            .get(connection_id)
            .filter(|connection| connection.provisioning_domain_id == provisioning_domain_id)
            .cloned())
    }

    async fn list_managed_credentials(
        &self,
        connection_record_id: &str,
    ) -> Result<Vec<ScimManagedCredential>, ScimStoreError> {
        let state = self.state.lock().await;
        Ok(state
            .managed_credentials
            .values()
            .filter(|credential| credential.connection_record_id == connection_record_id)
            .cloned()
            .collect())
    }

    async fn find_managed_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<(ScimManagedConnection, ScimManagedCredential)>, ScimStoreError> {
        let state = self.state.lock().await;
        let Some(credential) = state.managed_credentials.get(credential_id) else {
            return Ok(None);
        };
        let connection = state
            .managed_connections
            .values()
            .find(|connection| connection.id == credential.connection_record_id)
            .cloned();
        Ok(connection.map(|connection| (connection, credential.clone())))
    }

    async fn save_managed_credential(
        &self,
        credential: ScimManagedCredential,
        event: ScimManagedConnectionEvent,
    ) -> Result<ScimManagedCredential, ScimStoreError> {
        let mut state = self.state.lock().await;
        state
            .managed_credentials
            .insert(credential.credential_id.clone(), credential.clone());
        state.managed_events.push(event);
        Ok(credential)
    }

    async fn revoke_managed_credential(
        &self,
        connection_record_id: &str,
        credential_id: &str,
        actor_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ScimManagedCredential, ScimStoreError> {
        let mut state = self.state.lock().await;
        let credential = state
            .managed_credentials
            .get_mut(credential_id)
            .filter(|credential| credential.connection_record_id == connection_record_id)
            .ok_or(ScimStoreError::CredentialNotFound)?;
        credential.status = "revoked".into();
        let output = credential.clone();
        let sequence = state
            .managed_events
            .iter()
            .filter(|event| event.connection_record_id == connection_record_id)
            .count() as u64
            + 1;
        state.managed_events.push(ScimManagedConnectionEvent {
            id: super::random_urlsafe(32),
            connection_record_id: connection_record_id.into(),
            sequence,
            kind: "credential_revoked".into(),
            actor_id: actor_id.into(),
            credential_id: Some(credential_id.into()),
            created_at: now,
        });
        Ok(output)
    }

    async fn touch_managed_credential(
        &self,
        credential_id: &str,
        now: DateTime<Utc>,
        minimum_interval_seconds: u64,
    ) -> Result<(), ScimStoreError> {
        let mut state = self.state.lock().await;
        let credential = state
            .managed_credentials
            .get_mut(credential_id)
            .ok_or(ScimStoreError::CredentialNotFound)?;
        if credential.last_used_at.is_none_or(|last| {
            now - last >= Duration::seconds(minimum_interval_seconds as i64)
        }) {
            credential.last_used_at = Some(now);
        }
        Ok(())
    }

    async fn list_managed_events(
        &self,
        connection_record_id: &str,
    ) -> Result<Vec<ScimManagedConnectionEvent>, ScimStoreError> {
        let state = self.state.lock().await;
        let mut events = state
            .managed_events
            .iter()
            .filter(|event| event.connection_record_id == connection_record_id)
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by_key(|event| std::cmp::Reverse(event.sequence));
        events.truncate(100);
        Ok(events)
    }

    async fn decommission_connection(
        &self,
        connection_id: &str,
        provisioning_domain_id: &str,
        _actor_id: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, ScimStoreError> {
        let mut state = self.state.lock().await;
        decommission(&mut state, connection_id, provisioning_domain_id, now)
    }
}
