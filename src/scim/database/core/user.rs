use super::{auth_error, ensure_active_binding, equal, find_one, store_error};
use crate::{AuthError, DashAdapterSort, DashSortDirection, DatabaseTransaction, run_database_transaction};
use crate::scim::{ScimStoreError, ScimUser, store::StoredScimUser};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(in crate::scim::database) async fn create_user(
    database: &super::super::DatabaseScimStore,
    user: StoredScimUser,
) -> Result<StoredScimUser, ScimStoreError> {
    let store = database.store.clone();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            ensure_active_binding(&transaction, &user.connection_id).await?;
            ensure_unique(&transaction, &user.connection_id, &user.resource, None).await?;
            ensure_connection_user_unique(&transaction, &user).await?;
            upsert_subject(&transaction, &user).await?;
            let record = super::super::codec::user_record(&user).map_err(auth_error)?;
            let record = transaction.create_record("scimUser", record).await?;
            decode(&transaction, record).await
        })
    })
    .await
    .map_err(store_error)
}

pub(in crate::scim::database) async fn find_user(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    resource_id: &str,
) -> Result<Option<StoredScimUser>, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let resource_id = resource_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let filter = resource_filter(&connection_id, &resource_id);
            match find_one(&transaction, "scimUser", &filter).await? {
                Some(record) => decode(&transaction, record).await.map(Some),
                None => Ok(None),
            }
        })
    })
    .await
    .map_err(store_error)
}

pub(in crate::scim::database) async fn list_users(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
) -> Result<Vec<StoredScimUser>, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let records = transaction
                .find_records(
                    "scimUser",
                    &[equal("connectionId", json!(connection_id))],
                    None,
                    0,
                    Some(&DashAdapterSort {
                        field: "orderKey".into(),
                        direction: DashSortDirection::Asc,
                    }),
                    &[],
                )
                .await?;
            let mut users = Vec::with_capacity(records.len());
            for record in records {
                users.push(decode(&transaction, record).await?);
            }
            Ok(users)
        })
    })
    .await
    .map_err(store_error)
}

pub(in crate::scim::database) async fn replace_user(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    resource_id: &str,
    mut resource: ScimUser,
    now: DateTime<Utc>,
) -> Result<StoredScimUser, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let resource_id = resource_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            ensure_active_binding(&transaction, &connection_id).await?;
            let filter = resource_filter(&connection_id, &resource_id);
            let existing = find_one(&transaction, "scimUser", &filter)
                .await?
                .ok_or_else(|| auth_error(ScimStoreError::NotFound))?;
            ensure_unique(&transaction, &connection_id, &resource, Some(&resource_id)).await?;
            resource.id = Some(resource_id.clone());
            let update = super::super::codec::user_update_record(&connection_id, &resource, now)
                .map_err(auth_error)?;
            let record = transaction
                .update_record("scimUser", &filter, update)
                .await?
                .ok_or_else(|| auth_error(ScimStoreError::NotFound))?;
            touch_managed_subject(&transaction, &existing, &resource_id, now).await?;
            decode(&transaction, record).await
        })
    })
    .await
    .map_err(store_error)
}

pub(in crate::scim::database) async fn delete_user(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    resource_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<StoredScimUser>, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let resource_id = resource_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let filter = resource_filter(&connection_id, &resource_id);
            let Some(record) = find_one(&transaction, "scimUser", &filter).await? else {
                return Ok(None);
            };
            let user = decode(&transaction, record).await?;
            transaction
                .delete_records("scimGroupMember", &[equal("scimUserId", json!(resource_id))])
                .await?;
            transaction
                .delete_records("scimProjectionGrant", &[equal("scimUserId", json!(resource_id))])
                .await?;
            transaction.delete_records("scimUser", &filter).await?;
            if let Some(tombstone) = super::super::codec::tombstone_record(&user, now) {
                transaction.create_record("scimIdentityTombstone", tombstone).await?;
            }
            clear_subject(&transaction, &user, now).await?;
            Ok(Some(user))
        })
    })
    .await
    .map_err(store_error)
}

async fn decode(
    transaction: &Arc<dyn DatabaseTransaction>,
    record: Map<String, Value>,
) -> Result<StoredScimUser, AuthError> {
    let user_id = super::super::codec::string(&record, "userId").map_err(auth_error)?;
    let resource_id = super::super::codec::string(&record, "id").map_err(auth_error)?;
    let subject = find_one(transaction, "scimSubject", &[equal("userId", json!(user_id))]).await?;
    let profile_managed = subject.as_ref().is_some_and(|subject| {
        subject.get("profileSourceId").and_then(Value::as_str) == Some(resource_id.as_str())
    });
    super::super::codec::decode_user(&record, profile_managed).map_err(auth_error)
}

async fn ensure_unique(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    resource: &ScimUser,
    except_id: Option<&str>,
) -> Result<(), AuthError> {
    let user_name_key = super::super::keys::user_name(connection_id, &resource.user_name);
    ensure_key_available(transaction, "userNameKey", user_name_key, except_id, ScimStoreError::DuplicateUserName).await?;
    if let Some(external_id) = resource.external_id.as_deref() {
        let key = super::super::keys::user_external_id(connection_id, external_id);
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
    let found = find_one(transaction, "scimUser", &[equal(field, json!(key))]).await?;
    if found.as_ref().is_some_and(|record| {
        record.get("id").and_then(Value::as_str) != except_id
    }) {
        return Err(auth_error(error));
    }
    Ok(())
}

async fn ensure_connection_user_unique(
    transaction: &Arc<dyn DatabaseTransaction>,
    user: &StoredScimUser,
) -> Result<(), AuthError> {
    let key = super::super::keys::connection_user(&user.connection_id, &user.user_id);
    if find_one(transaction, "scimUser", &[equal("connectionUserKey", json!(key))])
        .await?
        .is_some()
    {
        return Err(auth_error(ScimStoreError::DuplicateUserName));
    }
    Ok(())
}

async fn upsert_subject(
    transaction: &Arc<dyn DatabaseTransaction>,
    user: &StoredScimUser,
) -> Result<(), AuthError> {
    let filter = [equal("userId", json!(user.user_id))];
    if let Some(subject) = find_one(transaction, "scimSubject", &filter).await? {
        if user.profile_managed {
            if subject
                .get("profileSourceId")
                .and_then(Value::as_str)
                .is_some_and(|source_id| user.resource.id.as_deref() != Some(source_id))
            {
                return Err(auth_error(ScimStoreError::ProfileConflict));
            }
            let revision = subject.get("revision").and_then(Value::as_i64).unwrap_or_default();
            transaction
                .increment_record(
                    "scimSubject",
                    &[equal("id", subject.get("id").cloned().unwrap_or(Value::Null)), equal("revision", json!(revision))],
                    super::super::codec::object(json!({"revision": 1})),
                    super::super::codec::object(json!({"profileSourceId": user.resource.id, "updatedAt": super::super::codec::date(user.updated_at)})),
                )
                .await?
                .ok_or_else(|| AuthError::Storage("SCIM subject revision changed".into()))?;
        }
    } else {
        transaction
            .create_record("scimSubject", super::super::codec::subject_record(user))
            .await?;
    }
    Ok(())
}

async fn touch_managed_subject(
    transaction: &Arc<dyn DatabaseTransaction>,
    user_record: &Map<String, Value>,
    resource_id: &str,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let user_id = super::super::codec::string(user_record, "userId").map_err(auth_error)?;
    let filter = [equal("userId", json!(user_id))];
    let Some(subject) = find_one(transaction, "scimSubject", &filter).await? else {
        return Ok(());
    };
    if subject.get("profileSourceId").and_then(Value::as_str) != Some(resource_id) {
        return Ok(());
    }
    increment_subject(transaction, subject, json!({"updatedAt": super::super::codec::date(now)})).await
}

async fn clear_subject(
    transaction: &Arc<dyn DatabaseTransaction>,
    user: &StoredScimUser,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let filter = [equal("userId", json!(user.user_id))];
    let Some(subject) = find_one(transaction, "scimSubject", &filter).await? else {
        return Ok(());
    };
    if !user.profile_managed {
        return Ok(());
    }
    increment_subject(transaction, subject, json!({"profileSourceId": null, "updatedAt": super::super::codec::date(now)})).await
}

async fn increment_subject(
    transaction: &Arc<dyn DatabaseTransaction>,
    subject: Map<String, Value>,
    set: Value,
) -> Result<(), AuthError> {
    let revision = subject.get("revision").and_then(Value::as_i64).unwrap_or_default();
    transaction
        .increment_record(
            "scimSubject",
            &[equal("id", subject.get("id").cloned().unwrap_or(Value::Null)), equal("revision", json!(revision))],
            super::super::codec::object(json!({"revision": 1})),
            super::super::codec::object(set),
        )
        .await?
        .ok_or_else(|| AuthError::Storage("SCIM subject revision changed".into()))?;
    Ok(())
}

fn resource_filter(connection_id: &str, resource_id: &str) -> [crate::DashAdapterWhere; 2] {
    [equal("connectionId", json!(connection_id)), equal("id", json!(resource_id))]
}
