use super::super::{NewSsoProvider, SsoProvider, SsoProviderUpdate, SsoStoreError};
use serde_json::{Map, Value, json};

pub(super) fn create_record(provider: NewSsoProvider) -> Result<Map<String, Value>, SsoStoreError> {
    let domain_verified = provider.domain_verified;
    let mut record = object(json!({
        "id": provider.id,
        "issuer": provider.issuer,
        "oidcConfig": encode_config(provider.oidc_config)?,
        "samlConfig": encode_config(provider.saml_config)?,
        "userId": provider.user_id,
        "providerId": provider.provider_id,
        "organizationId": provider.organization_id,
        "domain": provider.domain,
    }))?;
    insert(&mut record, "domainVerified", domain_verified);
    record.extend(provider.additional_fields);
    Ok(record)
}

pub(super) fn update_record(
    update: SsoProviderUpdate,
) -> Result<Map<String, Value>, SsoStoreError> {
    let mut record = Map::new();
    insert(&mut record, "issuer", update.issuer);
    insert_encoded(&mut record, "oidcConfig", update.oidc_config)?;
    insert_encoded(&mut record, "samlConfig", update.saml_config)?;
    insert(&mut record, "providerId", update.provider_id);
    insert(&mut record, "organizationId", update.organization_id);
    insert(&mut record, "domain", update.domain);
    insert(&mut record, "domainVerified", update.domain_verified);
    record.extend(update.additional_fields);
    Ok(record)
}

pub(super) fn decode(record: &Map<String, Value>) -> Result<SsoProvider, SsoStoreError> {
    let additional_fields = record
        .iter()
        .filter(|(field, _)| !is_built_in(field))
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect();
    Ok(SsoProvider {
        id: string(record, "id")?,
        issuer: string(record, "issuer")?,
        oidc_config: decode_config(record, "oidcConfig")?,
        saml_config: decode_config(record, "samlConfig")?,
        user_id: string(record, "userId")?,
        provider_id: string(record, "providerId")?,
        organization_id: optional_string(record, "organizationId")?,
        domain: string(record, "domain")?,
        domain_verified: optional_bool(record, "domainVerified")?,
        additional_fields,
    })
}

fn is_built_in(field: &str) -> bool {
    [
        "id",
        "issuer",
        "oidcConfig",
        "samlConfig",
        "userId",
        "providerId",
        "organizationId",
        "domain",
        "domainVerified",
    ]
    .contains(&field)
}

fn encode_config(value: Option<Value>) -> Result<Option<String>, SsoStoreError> {
    value
        .map(|value| serde_json::to_string(&value).map_err(storage))
        .transpose()
}

fn decode_config(record: &Map<String, Value>, field: &str) -> Result<Option<Value>, SsoStoreError> {
    optional_string(record, field)?
        .map(|value| serde_json::from_str(&value).map_err(storage))
        .transpose()
}

fn insert<T: serde::Serialize>(record: &mut Map<String, Value>, field: &str, value: Option<T>) {
    if let Some(value) = value {
        record.insert(field.into(), serde_json::to_value(value).expect("serializable field"));
    }
}

fn insert_encoded(
    record: &mut Map<String, Value>,
    field: &str,
    value: Option<Option<Value>>,
) -> Result<(), SsoStoreError> {
    if let Some(value) = value {
        record.insert(
            field.into(),
            encode_config(value)?.map_or(Value::Null, Value::String),
        );
    }
    Ok(())
}

fn object(value: Value) -> Result<Map<String, Value>, SsoStoreError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| SsoStoreError::Storage("SSO record is not an object".into()))
}

fn string(record: &Map<String, Value>, field: &str) -> Result<String, SsoStoreError> {
    record
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| SsoStoreError::Storage(format!("SSO record is missing {field}")))
}

fn optional_string(
    record: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, SsoStoreError> {
    match record.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(SsoStoreError::Storage(format!(
            "SSO record has invalid {field}"
        ))),
    }
}

fn optional_bool(
    record: &Map<String, Value>,
    field: &str,
) -> Result<Option<bool>, SsoStoreError> {
    match record.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(SsoStoreError::Storage(format!(
            "SSO record has invalid {field}"
        ))),
    }
}

fn storage(error: impl std::fmt::Display) -> SsoStoreError {
    SsoStoreError::Storage(error.to_string())
}
