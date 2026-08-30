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

pub(super) fn decommission_managed(
    state: &mut MemoryScimState,
    connection_id: &str,
    provisioning_domain_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<ScimManagedConnection, ScimStoreError> {
    let Some(mut connection) = state
        .managed_connections
        .get(connection_id)
        .filter(|connection| connection.provisioning_domain_id == provisioning_domain_id)
        .cloned()
    else {
        return Err(ScimStoreError::NotFound);
    };
    if connection.status == "decommissioned" {
        return Ok(connection);
    }
    if connection.status == "active" {
        connection.status = "decommissioning".into();
        connection.revision += 1;
        connection.decommission_started_at = Some(now);
        connection.decommission_started_by = Some(actor_id.into());
        push_event(
            state,
            &connection,
            "connection.decommissioning",
            actor_id,
            now,
        );
    }
    for credential in state.managed_credentials.values_mut().filter(|credential| {
        credential.connection_record_id == connection.id && credential.status == "active"
    }) {
        credential.status = "decommissioned".into();
    }
    state.users.retain(|_, user| user.connection_id != connection_id);
    state
        .groups
        .retain(|_, group| group.connection_id != connection_id);
    state.bindings.insert(
        connection_id.into(),
        ScimConnectionBinding {
            connection_id: connection_id.into(),
            provisioning_domain_id: provisioning_domain_id.into(),
            decommissioned_at: Some(now),
        },
    );
    connection.status = "decommissioned".into();
    connection.revision += 1;
    connection.decommissioned_at = Some(now);
    connection.decommissioned_by = Some(actor_id.into());
    push_event(
        state,
        &connection,
        "connection.decommissioned",
        actor_id,
        now,
    );
    state
        .managed_connections
        .insert(connection_id.into(), connection.clone());
    Ok(connection)
}

pub(super) fn rotate_credential(
    state: &mut MemoryScimState,
    connection_id: &str,
    provisioning_domain_id: &str,
    credential: ScimManagedCredential,
    event: ScimManagedConnectionEvent,
    maximum: usize,
    now: DateTime<Utc>,
) -> Result<(ScimManagedConnection, ScimManagedCredential), ScimStoreError> {
    let Some(mut connection) = state
        .managed_connections
        .get(connection_id)
        .filter(|connection| connection.provisioning_domain_id == provisioning_domain_id)
        .cloned()
    else {
        return Err(ScimStoreError::NotFound);
    };
    if connection.status != "active" {
        return Err(ScimStoreError::Decommissioned);
    }
    for existing in state.managed_credentials.values_mut().filter(|existing| {
        existing.connection_record_id == connection.id
            && existing.status == "active"
            && existing.expires_at <= now
    }) {
        existing.status = "expired".into();
    }
    let active = state
        .managed_credentials
        .values()
        .filter(|existing| {
            existing.connection_record_id == connection.id && existing.status == "active"
        })
        .count();
    if active >= maximum {
        return Err(ScimStoreError::CredentialLimit);
    }
    connection.revision += 1;
    state
        .managed_connections
        .insert(connection_id.into(), connection.clone());
    state
        .managed_credentials
        .insert(credential.credential_id.clone(), credential.clone());
    state.managed_events.push(event);
    Ok((connection, credential))
}

pub(super) fn revoke_credential(
    state: &mut MemoryScimState,
    connection_record_id: &str,
    credential_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<ScimManagedCredential, ScimStoreError> {
    let connection = state
        .managed_connections
        .values()
        .find(|connection| connection.id == connection_record_id)
        .ok_or(ScimStoreError::NotFound)?;
    if connection.status != "active" {
        return Err(ScimStoreError::Decommissioned);
    }
    let connection_id = connection.connection_id.clone();
    let credential = state
        .managed_credentials
        .get_mut(credential_id)
        .filter(|credential| credential.connection_record_id == connection_record_id)
        .ok_or(ScimStoreError::CredentialNotFound)?;
    if credential.status == "revoked" {
        return Ok(credential.clone());
    }
    if credential.status != "active" {
        return Err(ScimStoreError::CredentialLimit);
    }
    credential.status = "revoked".into();
    credential.revoked_at = Some(now);
    credential.revoked_by = Some(actor_id.into());
    let output = credential.clone();
    let sequence = state
        .managed_events
        .iter()
        .filter(|event| event.connection_record_id == connection_record_id)
        .count() as u64
        + 1;
    state.managed_events.push(ScimManagedConnectionEvent {
        id: crate::scim::random_urlsafe(32),
        connection_record_id: connection_record_id.into(),
        sequence,
        kind: "credential.revoked".into(),
        actor_id: actor_id.into(),
        credential_id: Some(credential_id.into()),
        created_at: now,
    });
    if let Some(connection) = state.managed_connections.get_mut(&connection_id) {
        connection.revision = sequence;
    }
    Ok(output)
}

fn push_event(
    state: &mut MemoryScimState,
    connection: &ScimManagedConnection,
    kind: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) {
    state.managed_events.push(ScimManagedConnectionEvent {
        id: crate::scim::random_urlsafe(32),
        connection_record_id: connection.id.clone(),
        sequence: connection.revision,
        kind: kind.into(),
        actor_id: actor_id.into(),
        credential_id: None,
        created_at: now,
    });
}
