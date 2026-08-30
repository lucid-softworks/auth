use crate::{AuthError, DashAdapterWhere, DatabaseTransaction};
use serde_json::{Map, Value};
use std::sync::Arc;

mod binding;
mod group;
mod user;

pub(super) use binding::bind_connection;
pub(super) use group::{
    create_group, delete_group, find_group, list_groups, replace_group,
};
pub(super) use user::{create_user, delete_user, find_user, list_users, replace_user};

pub(super) fn equal(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: Default::default(),
        connector: None,
    }
}

pub(super) async fn find_one(
    transaction: &Arc<dyn DatabaseTransaction>,
    model: &str,
    where_clause: &[DashAdapterWhere],
) -> Result<Option<Map<String, Value>>, AuthError> {
    transaction
        .find_records(model, where_clause, Some(1), 0, None, &[])
        .await
        .map(|mut rows| rows.pop())
}

pub(super) async fn ensure_active_binding(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
) -> Result<(), AuthError> {
    let filter = [equal(
        "connectionKey",
        serde_json::json!(super::keys::connection(connection_id)),
    )];
    let Some(record) = find_one(transaction, "scimConnectionBinding", &filter).await? else {
        return Ok(());
    };
    let binding = super::codec::decode_binding(&record).map_err(auth_error)?;
    if binding.decommissioned_at.is_some() {
        return Err(auth_error(crate::scim::ScimStoreError::Decommissioned));
    }
    Ok(())
}

pub(super) async fn fence_active_binding(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
) -> Result<(), AuthError> {
    transaction
        .increment_record(
            "scimConnectionBinding",
            &[
                equal(
                    "connectionKey",
                    serde_json::json!(super::keys::connection(connection_id)),
                ),
                equal("connectionId", serde_json::json!(connection_id)),
                equal("decommissionStatus", serde_json::json!("active")),
            ],
            super::codec::object(serde_json::json!({"decommissionRevision": 1})),
            serde_json::Map::new(),
        )
        .await?
        .ok_or_else(|| auth_error(crate::scim::ScimStoreError::Decommissioned))?;
    Ok(())
}

pub(super) fn auth_error(error: crate::scim::ScimStoreError) -> AuthError {
    AuthError::Storage(format!("{ERROR_PREFIX}{error:?}"))
}

pub(super) fn store_error(error: AuthError) -> crate::scim::ScimStoreError {
    let detail = error.to_string();
    let Some(marker) = detail.split_once(ERROR_PREFIX).map(|(_, marker)| marker) else {
        return crate::scim::ScimStoreError::Storage(detail);
    };
    match marker {
        "NotFound" => crate::scim::ScimStoreError::NotFound,
        "DuplicateUserName" => crate::scim::ScimStoreError::DuplicateUserName,
        "DuplicateExternalId" => crate::scim::ScimStoreError::DuplicateExternalId,
        "DuplicateDisplayName" => crate::scim::ScimStoreError::DuplicateDisplayName,
        "InvalidMember" => crate::scim::ScimStoreError::InvalidMember,
        "BindingConflict" => crate::scim::ScimStoreError::BindingConflict,
        "Decommissioned" => crate::scim::ScimStoreError::Decommissioned,
        "ProfileConflict" => crate::scim::ScimStoreError::ProfileConflict,
        "ConcurrentMutation" => crate::scim::ScimStoreError::ConcurrentMutation,
        "CreationRequestConflict" => crate::scim::ScimStoreError::CreationRequestConflict,
        "CredentialLimit" => crate::scim::ScimStoreError::CredentialLimit,
        "CredentialNotFound" => crate::scim::ScimStoreError::CredentialNotFound,
        _ => crate::scim::ScimStoreError::Storage(detail),
    }
}

const ERROR_PREFIX: &str = "__lucid_scim_store_error__:";
