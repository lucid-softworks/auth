use super::ScimIdentitySource;
use crate::{AuthError, DashAdapterWhere, DatabaseTransaction};
use chrono::Utc;
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(super) async fn sources(
    transaction: &Arc<dyn DatabaseTransaction>,
    provisioning_domain_id: &str,
    user_id: &str,
) -> Result<Vec<ScimIdentitySource>, super::ScimError> {
    let records = transaction
        .find_records(
            "scimUser",
            &[
                equal("userId", json!(user_id)),
                equal("provisioningDomainId", json!(provisioning_domain_id)),
            ],
            None,
            0,
            None,
            &[],
        )
        .await
        .map_err(database_error)?;
    let mut sources = Vec::new();
    for record in records {
        let connection_id = string(&record, "connectionId")?;
        if active_connection(transaction, &connection_id).await? {
            sources.push(ScimIdentitySource {
                id: string(&record, "id")?,
                connection_id,
                provisioning_domain_id: provisioning_domain_id.into(),
                active: boolean(&record, "active")?,
            });
        }
    }
    sources.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(sources)
}

pub(super) async fn lock(
    transaction: &Arc<dyn DatabaseTransaction>,
    user_id: &str,
) -> Result<(), super::ScimError> {
    let Some(subject) = find_one(
        transaction,
        "scimSubject",
        &[equal("userId", json!(user_id))],
    )
    .await?
    else {
        return Err(super::ScimError::new(
            500,
            "A SCIM User selected for projection has no subject aggregate",
        ));
    };
    let revision = subject
        .get("revision")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    transaction
        .increment_record(
            "scimSubject",
            &[
                equal("id", subject["id"].clone()),
                equal("revision", json!(revision)),
            ],
            object(json!({"revision": 1})),
            object(json!({"updatedAt": Utc::now().to_rfc3339()})),
        )
        .await
        .map_err(database_error)?
        .ok_or_else(|| {
            super::ScimError::retryable_conflict(
                "The SCIM projection subject changed concurrently; retry the request",
            )
        })?;
    Ok(())
}

async fn active_connection(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
) -> Result<bool, super::ScimError> {
    Ok(find_one(
        transaction,
        "scimConnectionBinding",
        &[
            equal("connectionId", json!(connection_id)),
            equal("decommissionStatus", json!("active")),
        ],
    )
    .await?
    .is_some())
}

pub(super) async fn find_one(
    transaction: &Arc<dyn DatabaseTransaction>,
    model: &str,
    filter: &[DashAdapterWhere],
) -> Result<Option<Map<String, Value>>, super::ScimError> {
    transaction
        .find_records(model, filter, Some(1), 0, None, &[])
        .await
        .map(|mut records| records.pop())
        .map_err(database_error)
}

pub(super) fn equal(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: Default::default(),
        connector: None,
    }
}

pub(super) fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("record is an object")
}

pub(super) fn string(
    record: &Map<String, Value>,
    field: &str,
) -> Result<String, super::ScimError> {
    record
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            super::ScimError::new(500, format!("stored SCIM field '{field}' is invalid"))
        })
}

pub(super) fn optional_string(
    record: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, super::ScimError> {
    match record.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(super::ScimError::new(
            500,
            format!("stored SCIM field '{field}' is invalid"),
        )),
    }
}

pub(super) fn boolean(
    record: &Map<String, Value>,
    field: &str,
) -> Result<bool, super::ScimError> {
    record
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            super::ScimError::new(500, format!("stored SCIM field '{field}' is invalid"))
        })
}

pub(super) fn database_error(error: AuthError) -> super::ScimError {
    super::ScimError::new(500, format!("SCIM projection storage failed: {error}"))
}
