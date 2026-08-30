use super::{auth_error, ensure_active_binding, equal, find_one, store_error};
use crate::{AuthError, DashAdapterSort, DashSortDirection, DatabaseTransaction, run_database_transaction};
use crate::scim::{ScimGroup, ScimGroupMember, ScimStoreError, store::StoredScimGroup};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(in crate::scim::database) async fn create_group(
    database: &super::super::DatabaseScimStore,
    group: StoredScimGroup,
) -> Result<StoredScimGroup, ScimStoreError> {
    let store = database.store.clone();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            ensure_active_binding(&transaction, &group.connection_id).await?;
            ensure_unique(&transaction, &group.connection_id, &group.resource, None).await?;
            ensure_members(&transaction, &group.connection_id, &group.resource.members).await?;
            let record = super::super::codec::group_record(&group).map_err(auth_error)?;
            let record = transaction.create_record("scimGroup", record).await?;
            create_memberships(&transaction, &group.connection_id, group.resource.id.as_deref().unwrap_or_default(), &group.resource.members, group.created_at).await?;
            decode(&transaction, record).await
        })
    })
    .await
    .map_err(store_error)
}

pub(in crate::scim::database) async fn find_group(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    resource_id: &str,
) -> Result<Option<StoredScimGroup>, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let resource_id = resource_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let filter = resource_filter(&connection_id, &resource_id);
            match find_one(&transaction, "scimGroup", &filter).await? {
                Some(record) => decode(&transaction, record).await.map(Some),
                None => Ok(None),
            }
        })
    })
    .await
    .map_err(store_error)
}

pub(in crate::scim::database) async fn list_groups(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
) -> Result<Vec<StoredScimGroup>, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let records = transaction
                .find_records(
                    "scimGroup",
                    &[equal("connectionId", json!(connection_id))],
                    None,
                    0,
                    Some(&DashAdapterSort { field: "orderKey".into(), direction: DashSortDirection::Asc }),
                    &[],
                )
                .await?;
            let mut groups = Vec::with_capacity(records.len());
            for record in records {
                groups.push(decode(&transaction, record).await?);
            }
            Ok(groups)
        })
    })
    .await
    .map_err(store_error)
}

pub(in crate::scim::database) async fn replace_group(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    resource_id: &str,
    mut resource: ScimGroup,
    now: DateTime<Utc>,
) -> Result<StoredScimGroup, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let resource_id = resource_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            ensure_active_binding(&transaction, &connection_id).await?;
            let filter = resource_filter(&connection_id, &resource_id);
            let existing = find_one(&transaction, "scimGroup", &filter)
                .await?
                .ok_or_else(|| auth_error(ScimStoreError::NotFound))?;
            ensure_unique(&transaction, &connection_id, &resource, Some(&resource_id)).await?;
            ensure_members(&transaction, &connection_id, &resource.members).await?;
            resource.id = Some(resource_id.clone());
            let revision = existing.get("revision").and_then(Value::as_i64).unwrap_or_default();
            let record = transaction
                .increment_record(
                    "scimGroup",
                    &[equal("id", json!(resource_id)), equal("revision", json!(revision))],
                    super::super::codec::object(json!({"revision": 1})),
                    group_update(&connection_id, &resource, now),
                )
                .await?
                .ok_or_else(|| AuthError::Storage("SCIM Group revision changed".into()))?;
            transaction.delete_records("scimGroupMember", &[equal("groupId", json!(resource_id))]).await?;
            create_memberships(&transaction, &connection_id, &resource_id, &resource.members, now).await?;
            decode(&transaction, record).await
        })
    })
    .await
    .map_err(store_error)
}

pub(in crate::scim::database) async fn delete_group(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    resource_id: &str,
) -> Result<Option<StoredScimGroup>, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let resource_id = resource_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let filter = resource_filter(&connection_id, &resource_id);
            let Some(record) = find_one(&transaction, "scimGroup", &filter).await? else {
                return Ok(None);
            };
            let group = decode(&transaction, record).await?;
            transaction.delete_records("scimGroupMember", &[equal("groupId", json!(resource_id))]).await?;
            transaction.delete_records("scimProjectionGrant", &[equal("sourceId", json!(resource_id))]).await?;
            transaction.delete_records("scimGroup", &filter).await?;
            Ok(Some(group))
        })
    })
    .await
    .map_err(store_error)
}

async fn decode(
    transaction: &Arc<dyn DatabaseTransaction>,
    record: Map<String, Value>,
) -> Result<StoredScimGroup, AuthError> {
    let group_id = super::super::codec::string(&record, "id").map_err(auth_error)?;
    let membership_records = transaction
        .find_records(
            "scimGroupMember",
            &[equal("groupId", json!(group_id))],
            None,
            0,
            Some(&DashAdapterSort { field: "createdAt".into(), direction: DashSortDirection::Asc }),
            &[],
        )
        .await?;
    let members = membership_records
        .iter()
        .map(|record| {
            Ok(ScimGroupMember {
                value: super::super::codec::string(record, "scimUserId").map_err(auth_error)?,
                kind: Some("User".into()),
                display: None,
                reference: None,
            })
        })
        .collect::<Result<Vec<_>, AuthError>>()?;
    super::super::codec::decode_group(&record, members).map_err(auth_error)
}

async fn ensure_unique(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    resource: &ScimGroup,
    except_id: Option<&str>,
) -> Result<(), AuthError> {
    let display_key = super::super::keys::group_display_name(connection_id, &resource.display_name);
    ensure_key_available(transaction, "displayNameKey", display_key, except_id, ScimStoreError::DuplicateDisplayName).await?;
    if let Some(external_id) = resource.external_id.as_deref() {
        let key = super::super::keys::group_external_id(connection_id, external_id);
        ensure_key_available(transaction, "externalIdKey", key, except_id, ScimStoreError::DuplicateExternalId).await?;
    }
    Ok(())
}

async fn ensure_key_available(
    transaction: &Arc<dyn DatabaseTransaction>,
    field: &str,
    key: String,
    except_id: Option<&str>,
    error: ScimStoreError,
) -> Result<(), AuthError> {
    let found = find_one(transaction, "scimGroup", &[equal(field, json!(key))]).await?;
    if found.as_ref().is_some_and(|record| record.get("id").and_then(Value::as_str) != except_id) {
        return Err(auth_error(error));
    }
    Ok(())
}

async fn ensure_members(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    members: &[ScimGroupMember],
) -> Result<(), AuthError> {
    for member in members {
        let filter = resource_filter(connection_id, &member.value);
        let Some(user) = find_one(transaction, "scimUser", &filter).await? else {
            return Err(auth_error(ScimStoreError::InvalidMember));
        };
        if user.get("active").and_then(Value::as_bool) != Some(true) {
            return Err(auth_error(ScimStoreError::InvalidMember));
        }
    }
    Ok(())
}

async fn create_memberships(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    group_id: &str,
    members: &[ScimGroupMember],
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    for member in members {
        let record = super::super::codec::membership_record(connection_id, group_id, &member.value, now);
        transaction.create_record("scimGroupMember", record).await?;
    }
    Ok(())
}

fn group_update(connection_id: &str, resource: &ScimGroup, now: DateTime<Utc>) -> Map<String, Value> {
    super::super::codec::object(json!({
        "displayName": resource.display_name,
        "displayNameKey": super::super::keys::group_display_name(connection_id, &resource.display_name),
        "externalId": resource.external_id,
        "externalIdKey": resource.external_id.as_deref().map(|external_id| super::super::keys::group_external_id(connection_id, external_id)),
        "updatedAt": super::super::codec::date(now),
    }))
}

fn resource_filter(connection_id: &str, resource_id: &str) -> [crate::DashAdapterWhere; 2] {
    [equal("connectionId", json!(connection_id)), equal("id", json!(resource_id))]
}
