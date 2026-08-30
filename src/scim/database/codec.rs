use super::keys;
use crate::scim::{
    SCIM_ENTERPRISE_USER_SCHEMA, ScimConnectionBinding, ScimGroup, ScimGroupMember, ScimStoreError,
    ScimUser,
    store::{StoredScimGroup, StoredScimUser},
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

pub(super) fn binding_record(
    connection_id: &str,
    provisioning_domain_id: &str,
    now: DateTime<Utc>,
) -> Map<String, Value> {
    object(json!({
        "id": crate::scim::random_urlsafe(32),
        "connectionId": connection_id,
        "connectionKey": keys::connection(connection_id),
        "provisioningDomainId": provisioning_domain_id,
        "createdAt": date(now),
        "decommissionedAt": null,
        "decommissionStatus": "active",
        "decommissionCursorUserId": null,
        "decommissionReconciledUserCount": 0,
        "decommissionBatchCount": 0,
        "decommissionRevision": 0,
        "decommissionCompletedAt": null,
        "decommissionLeaseId": null,
        "decommissionLeaseExpiresAt": null,
    }))
}

pub(super) fn decode_binding(
    record: &Map<String, Value>,
) -> Result<ScimConnectionBinding, ScimStoreError> {
    Ok(ScimConnectionBinding {
        connection_id: string(record, "connectionId")?,
        provisioning_domain_id: string(record, "provisioningDomainId")?,
        decommissioned_at: optional_date(record, "decommissionedAt")?,
    })
}

pub(super) fn subject_record(user: &StoredScimUser) -> Map<String, Value> {
    object(json!({
        "id": crate::scim::random_urlsafe(32),
        "userId": user.user_id,
        "profileSourceId": if user.profile_managed { user.resource.id.clone() } else { None },
        "revision": 0,
        "createdAt": date(user.created_at),
        "updatedAt": date(user.updated_at),
    }))
}

pub(super) fn user_record(user: &StoredScimUser) -> Result<Map<String, Value>, ScimStoreError> {
    let resource_id = user
        .resource
        .id
        .as_deref()
        .ok_or_else(|| invalid("SCIM User resource id is missing"))?;
    let name = user.resource.name.as_ref().ok_or_else(|| {
        invalid("normalized SCIM User name is missing")
    })?;
    let formatted = name.formatted.as_deref().ok_or_else(|| {
        invalid("normalized SCIM User formatted name is missing")
    })?;
    let display_name = user.resource.display_name.as_deref().ok_or_else(|| {
        invalid("normalized SCIM User display name is missing")
    })?;
    let attributes = serialized_user_attributes(&user.resource)?;
    let serialized_emails = serde_json::to_string(&user.resource.emails).map_err(json_error)?;
    Ok(object(json!({
        "id": resource_id,
        "connectionId": user.connection_id,
        "provisioningDomainId": user.provisioning_domain_id,
        "userId": user.user_id,
        "connectionUserKey": keys::connection_user(&user.connection_id, &user.user_id),
        "userName": user.resource.user_name,
        "userNameKey": keys::user_name(&user.connection_id, &user.resource.user_name),
        "primaryEmail": user.resource.primary_email(),
        "workEmailValueIndex": email_index(&user.resource, Some("work")),
        "emailValueIndex": email_index(&user.resource, None),
        "displayName": display_name,
        "formattedName": formatted,
        "givenName": name.given_name,
        "familyName": name.family_name,
        "serializedEmails": serialized_emails,
        "serializedAttributes": attributes,
        "externalId": user.resource.external_id,
        "externalIdKey": user.resource.external_id.as_deref().map(|external_id| keys::user_external_id(&user.connection_id, external_id)),
        "active": user.resource.active,
        "orderKey": order_key(user.created_at),
        "createdAt": date(user.created_at),
        "updatedAt": date(user.updated_at),
    })))
}

pub(super) fn user_update_record(
    connection_id: &str,
    resource: &ScimUser,
    now: DateTime<Utc>,
) -> Result<Map<String, Value>, ScimStoreError> {
    let name = resource.name.as_ref().ok_or_else(|| {
        invalid("normalized SCIM User name is missing")
    })?;
    let formatted = name.formatted.as_deref().ok_or_else(|| {
        invalid("normalized SCIM User formatted name is missing")
    })?;
    let display_name = resource.display_name.as_deref().ok_or_else(|| {
        invalid("normalized SCIM User display name is missing")
    })?;
    Ok(object(json!({
        "userName": resource.user_name,
        "userNameKey": keys::user_name(connection_id, &resource.user_name),
        "primaryEmail": resource.primary_email(),
        "workEmailValueIndex": email_index(resource, Some("work")),
        "emailValueIndex": email_index(resource, None),
        "displayName": display_name,
        "formattedName": formatted,
        "givenName": name.given_name,
        "familyName": name.family_name,
        "serializedEmails": serde_json::to_string(&resource.emails).map_err(json_error)?,
        "serializedAttributes": serialized_user_attributes(resource)?,
        "externalId": resource.external_id,
        "externalIdKey": resource.external_id.as_deref().map(|external_id| keys::user_external_id(connection_id, external_id)),
        "active": resource.active,
        "updatedAt": date(now),
    })))
}

pub(super) fn decode_user(
    record: &Map<String, Value>,
    profile_managed: bool,
) -> Result<StoredScimUser, ScimStoreError> {
    let serialized = string(record, "serializedAttributes")?;
    let mut resource = serde_json::from_str::<Value>(&serialized).map_err(json_error)?;
    let attributes = resource
        .as_object_mut()
        .ok_or_else(|| invalid("stored SCIM User attributes are not an object"))?;
    if let Some(enterprise) = attributes.remove("enterprise") {
        attributes.insert(SCIM_ENTERPRISE_USER_SCHEMA.into(), enterprise);
    }
    attributes.insert("id".into(), record.get("id").cloned().unwrap_or(Value::Null));
    attributes.insert(
        "externalId".into(),
        record.get("externalId").cloned().unwrap_or(Value::Null),
    );
    attributes.insert("userName".into(), json!(string(record, "userName")?));
    attributes.insert("displayName".into(), json!(string(record, "displayName")?));
    attributes.insert("active".into(), json!(boolean(record, "active")?));
    attributes.retain(|_, value| !value.is_null());
    let resource = serde_json::from_value(resource).map_err(json_error)?;
    Ok(StoredScimUser {
        resource,
        connection_id: string(record, "connectionId")?,
        provisioning_domain_id: string(record, "provisioningDomainId")?,
        user_id: string(record, "userId")?,
        profile_managed,
        created_at: required_date(record, "createdAt")?,
        updated_at: required_date(record, "updatedAt")?,
    })
}

pub(super) fn group_record(group: &StoredScimGroup) -> Result<Map<String, Value>, ScimStoreError> {
    let id = group
        .resource
        .id
        .as_deref()
        .ok_or_else(|| invalid("SCIM Group resource id is missing"))?;
    Ok(object(json!({
        "id": id,
        "connectionId": group.connection_id,
        "provisioningDomainId": group.provisioning_domain_id,
        "revision": 0,
        "displayName": group.resource.display_name,
        "displayNameKey": keys::group_display_name(&group.connection_id, &group.resource.display_name),
        "externalId": group.resource.external_id,
        "externalIdKey": group.resource.external_id.as_deref().map(|external_id| keys::group_external_id(&group.connection_id, external_id)),
        "orderKey": order_key(group.created_at),
        "createdAt": date(group.created_at),
        "updatedAt": date(group.updated_at),
    })))
}

pub(super) fn decode_group(
    record: &Map<String, Value>,
    members: Vec<ScimGroupMember>,
) -> Result<StoredScimGroup, ScimStoreError> {
    Ok(StoredScimGroup {
        resource: ScimGroup {
            schemas: vec![crate::scim::SCIM_GROUP_SCHEMA.into()],
            id: Some(string(record, "id")?),
            external_id: optional_string(record, "externalId")?,
            display_name: string(record, "displayName")?,
            members,
            meta: None,
        },
        connection_id: string(record, "connectionId")?,
        provisioning_domain_id: string(record, "provisioningDomainId")?,
        created_at: required_date(record, "createdAt")?,
        updated_at: required_date(record, "updatedAt")?,
    })
}

pub(super) fn membership_record(
    connection_id: &str,
    group_id: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> Map<String, Value> {
    object(json!({
        "id": crate::scim::random_urlsafe(32),
        "connectionId": connection_id,
        "groupId": group_id,
        "scimUserId": user_id,
        "membershipKey": keys::membership(connection_id, group_id, user_id),
        "createdAt": date(now),
    }))
}

pub(super) fn tombstone_record(user: &StoredScimUser, now: DateTime<Utc>) -> Option<Map<String, Value>> {
    let external_id = user.resource.external_id.as_deref()?;
    Some(object(json!({
        "id": crate::scim::random_urlsafe(32),
        "connectionId": user.connection_id,
        "provisioningDomainId": user.provisioning_domain_id,
        "externalId": external_id,
        "externalIdKey": keys::user_external_id(&user.connection_id, external_id),
        "userId": user.user_id,
        "profile": if user.profile_managed { "manage" } else { "preserve" },
        "deletedAt": date(now),
    })))
}

fn serialized_user_attributes(resource: &ScimUser) -> Result<String, ScimStoreError> {
    let mut value = serde_json::to_value(resource).map_err(json_error)?;
    let attributes = value
        .as_object_mut()
        .ok_or_else(|| invalid("SCIM User attributes are not an object"))?;
    for field in ["id", "externalId", "userName", "displayName", "active", "meta"] {
        attributes.remove(field);
    }
    if let Some(enterprise) = attributes.remove(SCIM_ENTERPRISE_USER_SCHEMA) {
        attributes.insert("enterprise".into(), enterprise);
    }
    serde_json::to_string(&value).map_err(json_error)
}

fn email_index(resource: &ScimUser, kind: Option<&str>) -> String {
    let tokens = resource
        .emails
        .iter()
        .filter(|email| kind.is_none_or(|kind| email.kind.as_deref() == Some(kind)))
        .map(|email| keys::email_value(&email.value))
        .collect::<std::collections::BTreeSet<_>>();
    format!("|{}|", tokens.into_iter().collect::<Vec<_>>().join("|"))
}

fn order_key(created_at: DateTime<Utc>) -> String {
    format!(
        "{:015}:{}",
        created_at.timestamp_millis(),
        crate::scim::random_urlsafe(16)
    )
}

pub(super) fn date(value: DateTime<Utc>) -> Value {
    Value::String(value.to_rfc3339())
}

pub(super) fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("record literal is an object")
}

pub(super) fn string(record: &Map<String, Value>, field: &str) -> Result<String, ScimStoreError> {
    record
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("stored SCIM field '{field}' is invalid")))
}

pub(super) fn optional_string(
    record: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, ScimStoreError> {
    match record.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(invalid(format!("stored SCIM field '{field}' is invalid"))),
    }
}

pub(super) fn boolean(record: &Map<String, Value>, field: &str) -> Result<bool, ScimStoreError> {
    record
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(format!("stored SCIM field '{field}' is invalid")))
}

pub(super) fn required_date(
    record: &Map<String, Value>,
    field: &str,
) -> Result<DateTime<Utc>, ScimStoreError> {
    optional_date(record, field)?
        .ok_or_else(|| invalid(format!("stored SCIM field '{field}' is invalid")))
}

pub(super) fn optional_date(
    record: &Map<String, Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, ScimStoreError> {
    optional_string(record, field)?
        .map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| invalid(format!("stored SCIM field '{field}' is invalid")))
        })
        .transpose()
}

fn json_error(error: impl std::fmt::Display) -> ScimStoreError {
    invalid(format!("stored SCIM JSON is invalid: {error}"))
}

fn invalid(detail: impl Into<String>) -> ScimStoreError {
    ScimStoreError::Storage(detail.into())
}
