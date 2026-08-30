use crate::scim::{
    ScimConnectionBinding, ScimManagedConnection, ScimManagedConnectionEvent,
    ScimManagedCredential, ScimStoreError,
    store::{StoredScimGroup, StoredScimUser},
};
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Default)]
pub(super) struct MemoryScimState {
    pub bindings: HashMap<String, ScimConnectionBinding>,
    pub users: BTreeMap<String, StoredScimUser>,
    pub groups: BTreeMap<String, StoredScimGroup>,
    pub tombstones: HashMap<(String, String), (String, String)>,
    pub creation_requests: HashSet<String>,
    pub managed_connections: BTreeMap<String, ScimManagedConnection>,
    pub managed_credentials: BTreeMap<String, ScimManagedCredential>,
    pub managed_events: Vec<ScimManagedConnectionEvent>,
}

pub(super) fn ensure_active_binding(
    state: &MemoryScimState,
    connection_id: &str,
) -> Result<(), ScimStoreError> {
    if state
        .bindings
        .get(connection_id)
        .is_some_and(|binding| binding.decommissioned_at.is_some())
    {
        Err(ScimStoreError::Decommissioned)
    } else {
        Ok(())
    }
}

pub(super) fn ensure_user_unique(
    state: &MemoryScimState,
    candidate: &StoredScimUser,
    except_id: Option<&str>,
) -> Result<(), ScimStoreError> {
    for user in state.users.values().filter(|user| {
        user.connection_id == candidate.connection_id
            && user.resource.id.as_deref() != except_id
    }) {
        if user
            .resource
            .user_name
            .eq_ignore_ascii_case(&candidate.resource.user_name)
        {
            return Err(ScimStoreError::DuplicateUserName);
        }
        if candidate.resource.external_id.is_some()
            && user.resource.external_id == candidate.resource.external_id
        {
            return Err(ScimStoreError::DuplicateExternalId);
        }
    }
    Ok(())
}

pub(super) fn ensure_group_unique(
    state: &MemoryScimState,
    candidate: &StoredScimGroup,
    except_id: Option<&str>,
) -> Result<(), ScimStoreError> {
    for group in state.groups.values().filter(|group| {
        group.connection_id == candidate.connection_id
            && group.resource.id.as_deref() != except_id
    }) {
        if group
            .resource
            .display_name
            .eq_ignore_ascii_case(&candidate.resource.display_name)
        {
            return Err(ScimStoreError::DuplicateDisplayName);
        }
        if candidate.resource.external_id.is_some()
            && group.resource.external_id == candidate.resource.external_id
        {
            return Err(ScimStoreError::DuplicateExternalId);
        }
    }
    Ok(())
}

pub(super) fn ensure_group_members(
    state: &MemoryScimState,
    group: &StoredScimGroup,
) -> Result<(), ScimStoreError> {
    if group.resource.members.iter().all(|member| {
        state.users.get(&member.value).is_some_and(|user| {
            user.connection_id == group.connection_id && user.resource.active
        })
    }) {
        Ok(())
    } else {
        Err(ScimStoreError::InvalidMember)
    }
}

pub(super) fn decommission(
    state: &mut MemoryScimState,
    connection_id: &str,
    provisioning_domain_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, ScimStoreError> {
    let binding = state
        .bindings
        .get_mut(connection_id)
        .ok_or(ScimStoreError::NotFound)?;
    if binding.provisioning_domain_id != provisioning_domain_id {
        return Err(ScimStoreError::NotFound);
    }
    binding.decommissioned_at = Some(now);
    let user_ids = state
        .users
        .values()
        .filter(|user| user.connection_id == connection_id)
        .filter_map(|user| user.resource.id.clone())
        .collect::<Vec<_>>();
    for user_id in &user_ids {
        state.users.remove(user_id);
    }
    let record_id = state
        .managed_connections
        .get(connection_id)
        .map(|connection| connection.id.as_str());
    for credential in state.managed_credentials.values_mut() {
        if record_id.is_some_and(|id| id == credential.connection_record_id) {
            credential.status = "decommissioned".into();
        }
    }
    if let Some(connection) = state.managed_connections.get_mut(connection_id) {
        connection.status = "decommissioned".into();
        connection.revision += 1;
    }
    Ok(user_ids.len())
}
