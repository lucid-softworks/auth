use crate::{
    AuthError, Organization, OrganizationInvitation, OrganizationRole, OrganizationTeamMember,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub(super) fn organization_record(
    store: &super::super::MssqlStore,
    value: &Organization,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = serde_json::to_value(value)
        .map_err(storage)?
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::Storage("organization is not an object".into()))?;
    record.insert(
        "metadata".into(),
        value
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(storage)?
            .map_or(Value::Null, Value::String),
    );
    retain(store, "organization", record)
}

pub(super) fn decode_organization(
    mut record: Map<String, Value>,
) -> Result<Organization, AuthError> {
    let metadata = optional_string(record.remove("metadata"), "metadata")?
        .map(|value| serde_json::from_str(&value).map_err(storage))
        .transpose()?;
    record.insert("metadata".into(), metadata.unwrap_or(Value::Null));
    serde_json::from_value(Value::Object(record)).map_err(storage)
}

pub(super) fn invitation_record(
    store: &super::super::MssqlStore,
    value: &OrganizationInvitation,
) -> Result<Map<String, Value>, AuthError> {
    let model = store.physical_schema()?.model("invitation")?;
    if value.team_id.is_some() && !model.has_field("teamId") {
        return Err(AuthError::InvalidConfiguration(
            "organization invitation teamId requires Better Auth team support".into(),
        ));
    }
    let mut record = serde_json::to_value(value)
        .map_err(storage)?
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::Storage("invitation is not an object".into()))?;
    record.insert("email".into(), Value::String(value.email.to_lowercase()));
    retain(store, "invitation", record)
}

pub(super) fn team_member_record(
    store: &super::super::MssqlStore,
    value: &OrganizationTeamMember,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = serde_json::to_value(value)
        .map_err(storage)?
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::Storage("team member is not an object".into()))?;
    if store
        .physical_schema()?
        .model("teamMember")?
        .has_field("membershipKey")
    {
        record.insert(
            "membershipKey".into(),
            Value::String(membership_key(&value.team_id, &value.user_id)),
        );
    }
    retain(store, "teamMember", record)
}

pub(super) fn role_record(
    store: &super::super::MssqlStore,
    value: &OrganizationRole,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = serde_json::to_value(value)
        .map_err(storage)?
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::Storage("organization role is not an object".into()))?;
    record.insert(
        "permission".into(),
        Value::String(serde_json::to_string(&value.permission).map_err(storage)?),
    );
    retain(store, "organizationRole", record)
}

pub(super) fn decode_role(mut record: Map<String, Value>) -> Result<OrganizationRole, AuthError> {
    let permission = string(record.remove("permission"), "permission")?;
    record.insert(
        "permission".into(),
        serde_json::from_str(&permission).map_err(storage)?,
    );
    serde_json::from_value(Value::Object(record)).map_err(storage)
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(
    model: &str,
    record: Map<String, Value>,
) -> Result<T, AuthError> {
    serde_json::from_value(Value::Object(record))
        .map_err(|error| AuthError::Storage(format!("invalid MSSQL {model} row: {error}")))
}

fn retain(
    store: &super::super::MssqlStore,
    model: &str,
    mut record: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    let model = store.physical_schema()?.model(model)?;
    record.retain(|field, _| model.has_field(field));
    Ok(record)
}

fn membership_key(team_id: &str, user_id: &str) -> String {
    let input = serde_json::to_vec(&[team_id, user_id]).expect("strings serialize");
    URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

fn optional_string(value: Option<Value>, field: &str) -> Result<Option<String>, AuthError> {
    match value {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) | None => Ok(None),
        _ => Err(AuthError::Storage(format!(
            "invalid MSSQL organization row: {field}"
        ))),
    }
}

fn string(value: Option<Value>, field: &str) -> Result<String, AuthError> {
    match value {
        Some(Value::String(value)) => Ok(value),
        _ => Err(AuthError::Storage(format!(
            "invalid MSSQL organizationRole row: {field}"
        ))),
    }
}

fn storage(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
