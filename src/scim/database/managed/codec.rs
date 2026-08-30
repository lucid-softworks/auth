use crate::scim::{
    ScimManagedConnection, ScimManagedConnectionEvent, ScimManagedCredential, ScimScope,
    ScimStoreError,
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

pub(super) fn connection_record(connection: &ScimManagedConnection) -> Map<String, Value> {
    object(json!({
        "id": connection.id,
        "creationRequestId": connection.creation_request_id,
        "connectionId": connection.connection_id,
        "provisioningDomainId": connection.provisioning_domain_id,
        "status": connection.status,
        "revision": connection.revision,
        "createdAt": date(connection.created_at),
        "createdBy": connection.created_by,
        "decommissionStartedAt": optional_date_value(connection.decommission_started_at),
        "decommissionStartedBy": connection.decommission_started_by,
        "decommissionedAt": optional_date_value(connection.decommissioned_at),
        "decommissionedBy": connection.decommissioned_by,
    }))
}

pub(super) fn decode_connection(
    record: &Map<String, Value>,
) -> Result<ScimManagedConnection, ScimStoreError> {
    Ok(ScimManagedConnection {
        id: string(record, "id")?,
        creation_request_id: string(record, "creationRequestId")?,
        connection_id: string(record, "connectionId")?,
        provisioning_domain_id: string(record, "provisioningDomainId")?,
        status: string(record, "status")?,
        revision: number(record, "revision")?,
        created_at: required_date(record, "createdAt")?,
        created_by: string(record, "createdBy")?,
        decommission_started_at: optional_date(record, "decommissionStartedAt")?,
        decommission_started_by: optional_string(record, "decommissionStartedBy")?,
        decommissioned_at: optional_date(record, "decommissionedAt")?,
        decommissioned_by: optional_string(record, "decommissionedBy")?,
    })
}

pub(super) fn credential_record(credential: &ScimManagedCredential) -> Map<String, Value> {
    object(json!({
        "id": credential.id,
        "connectionRecordId": credential.connection_record_id,
        "credentialId": credential.credential_id,
        "tokenDigest": credential.token_digest,
        "hashVersion": credential.hash_version,
        "activeSlotKey": credential.active_slot_key,
        "status": credential.status,
        "serializedScopes": credential.serialized_scopes,
        "expiresAt": date(credential.expires_at),
        "createdAt": date(credential.created_at),
        "createdBy": credential.created_by,
        "lastUsedAt": optional_date_value(credential.last_used_at),
        "revokedAt": optional_date_value(credential.revoked_at),
        "revokedBy": credential.revoked_by,
        "decommissionedAt": optional_date_value(credential.decommissioned_at),
    }))
}

pub(super) fn decode_credential(
    record: &Map<String, Value>,
) -> Result<ScimManagedCredential, ScimStoreError> {
    let serialized_scopes = string(record, "serializedScopes")?;
    Ok(ScimManagedCredential {
        id: string(record, "id")?,
        connection_record_id: string(record, "connectionRecordId")?,
        credential_id: string(record, "credentialId")?,
        token_digest: string(record, "tokenDigest")?,
        hash_version: string(record, "hashVersion")?,
        active_slot_key: string(record, "activeSlotKey")?,
        status: string(record, "status")?,
        scopes: scopes(&serialized_scopes)?,
        serialized_scopes,
        expires_at: required_date(record, "expiresAt")?,
        created_at: required_date(record, "createdAt")?,
        created_by: string(record, "createdBy")?,
        last_used_at: optional_date(record, "lastUsedAt")?,
        revoked_at: optional_date(record, "revokedAt")?,
        revoked_by: optional_string(record, "revokedBy")?,
        decommissioned_at: optional_date(record, "decommissionedAt")?,
    })
}

pub(super) fn event_record(event: &ScimManagedConnectionEvent) -> Map<String, Value> {
    object(json!({
        "id": event.id,
        "connectionRecordId": event.connection_record_id,
        "eventKey": format!("{}:{}", event.connection_record_id, event.sequence),
        "sequence": event.sequence,
        "type": event.kind,
        "actorId": event.actor_id,
        "credentialId": event.credential_id,
        "createdAt": date(event.created_at),
    }))
}

pub(super) fn decode_event(
    record: &Map<String, Value>,
) -> Result<ScimManagedConnectionEvent, ScimStoreError> {
    Ok(ScimManagedConnectionEvent {
        id: string(record, "id")?,
        connection_record_id: string(record, "connectionRecordId")?,
        sequence: number(record, "sequence")?,
        kind: string(record, "type")?,
        actor_id: string(record, "actorId")?,
        credential_id: optional_string(record, "credentialId")?,
        created_at: required_date(record, "createdAt")?,
    })
}

pub(super) fn event(
    connection_record_id: &str,
    sequence: u64,
    kind: &str,
    actor_id: &str,
    credential_id: Option<&str>,
    now: DateTime<Utc>,
) -> ScimManagedConnectionEvent {
    ScimManagedConnectionEvent {
        id: crate::scim::random_urlsafe(32),
        connection_record_id: connection_record_id.into(),
        sequence,
        kind: kind.into(),
        actor_id: actor_id.into(),
        credential_id: credential_id.map(str::to_owned),
        created_at: now,
    }
}

pub(super) fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("managed record is an object")
}

pub(super) fn date(value: DateTime<Utc>) -> Value {
    Value::String(value.to_rfc3339())
}

fn optional_date_value(value: Option<DateTime<Utc>>) -> Value {
    value.map(date).unwrap_or(Value::Null)
}

fn scopes(serialized: &str) -> Result<Vec<ScimScope>, ScimStoreError> {
    let values = serde_json::from_str::<Vec<String>>(serialized).map_err(json_error)?;
    values
        .into_iter()
        .map(|value| match value.as_str() {
            "scim.users.read" => Ok(ScimScope::UsersRead),
            "scim.users.write" => Ok(ScimScope::UsersWrite),
            "scim.groups.read" => Ok(ScimScope::GroupsRead),
            "scim.groups.write" => Ok(ScimScope::GroupsWrite),
            _ => Err(invalid("managed credential scope policy is invalid")),
        })
        .collect()
}

fn string(record: &Map<String, Value>, field: &str) -> Result<String, ScimStoreError> {
    record
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("managed field '{field}' is invalid")))
}

fn optional_string(
    record: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, ScimStoreError> {
    match record.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(invalid(format!("managed field '{field}' is invalid"))),
    }
}

fn number(record: &Map<String, Value>, field: &str) -> Result<u64, ScimStoreError> {
    record
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(format!("managed field '{field}' is invalid")))
}

fn required_date(
    record: &Map<String, Value>,
    field: &str,
) -> Result<DateTime<Utc>, ScimStoreError> {
    optional_date(record, field)?
        .ok_or_else(|| invalid(format!("managed field '{field}' is invalid")))
}

fn optional_date(
    record: &Map<String, Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, ScimStoreError> {
    optional_string(record, field)?
        .map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| invalid(format!("managed field '{field}' is invalid")))
        })
        .transpose()
}

fn json_error(error: impl std::fmt::Display) -> ScimStoreError {
    invalid(format!("managed JSON is invalid: {error}"))
}

fn invalid(detail: impl Into<String>) -> ScimStoreError {
    ScimStoreError::Storage(detail.into())
}
