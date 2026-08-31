use super::MongoStore;
use crate::{AuthError, OAuthAccount, store::PreparedDatabaseId};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};

pub(super) fn create_record<T: Serialize>(
    store: &MongoStore,
    model_name: &str,
    value: &T,
    id: &PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = object(value)?;
    if let PreparedDatabaseId::Value(value) = id {
        record.insert("id".into(), value.to_json()?);
    } else {
        record.remove("id");
    }
    retain_schema_fields(store, model_name, record)
}

pub(super) fn update_record<T: Serialize>(
    store: &MongoStore,
    model_name: &str,
    value: &T,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = object(value)?;
    record.remove("id");
    retain_schema_fields(store, model_name, record)
}

pub(super) fn oauth_create_record(
    store: &MongoStore,
    account: &OAuthAccount,
    id: &PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = object(account)?;
    insert_oauth_secrets(&mut record, account);
    if let PreparedDatabaseId::Value(value) = id {
        record.insert("id".into(), value.to_json()?);
    } else {
        record.remove("id");
    }
    retain_schema_fields(store, "account", record)
}

pub(super) fn oauth_update_record(
    store: &MongoStore,
    account: &OAuthAccount,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = object(account)?;
    insert_oauth_secrets(&mut record, account);
    record.remove("id");
    retain_schema_fields(store, "account", record)
}

pub(super) fn api_key_create_record(
    store: &MongoStore,
    key: &crate::ApiKey,
    id: &PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = object(key)?;
    record.insert("key".into(), json!(key.key_hash));
    if let PreparedDatabaseId::Value(value) = id {
        record.insert("id".into(), value.to_json()?);
    } else {
        record.remove("id");
    }
    retain_schema_fields(store, "apikey", record)
}

pub(super) fn api_key_update_record(
    store: &MongoStore,
    key: &crate::ApiKey,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = object(key)?;
    record.insert("key".into(), json!(key.key_hash));
    record.remove("id");
    retain_schema_fields(store, "apikey", record)
}

pub(super) fn decode<T: DeserializeOwned>(
    model: &str,
    mut record: Map<String, Value>,
) -> Result<T, AuthError> {
    add_transient_defaults(model, &mut record);
    serde_json::from_value(Value::Object(record))
        .map_err(|error| AuthError::Storage(format!("invalid MongoDB {model} row: {error}")))
}

pub(super) fn decode_oauth(mut record: Map<String, Value>) -> Result<OAuthAccount, AuthError> {
    let access_token = optional_string(record.remove("accessToken"), "accessToken")?;
    let refresh_token = optional_string(record.remove("refreshToken"), "refreshToken")?;
    let id_token = optional_string(record.remove("idToken"), "idToken")?;
    let password = optional_string(record.remove("password"), "password")?;
    let mut account: OAuthAccount = decode("account", record)?;
    account.access_token = access_token;
    account.refresh_token = refresh_token;
    account.id_token = id_token;
    account.password = password;
    Ok(account)
}

pub(super) fn decode_api_key(mut record: Map<String, Value>) -> Result<crate::ApiKey, AuthError> {
    let key_hash = match record.remove("key") {
        Some(Value::String(value)) => value,
        _ => return Err(AuthError::Storage("invalid MongoDB apikey row: key".into())),
    };
    record.insert("keyHash".into(), Value::String(key_hash));
    decode("apikey", record)
}

fn retain_schema_fields(
    store: &MongoStore,
    model_name: &str,
    mut record: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    let model = store.physical_schema()?.model(model_name)?;
    record.retain(|field, _| model.has_field(field));
    Ok(record)
}

fn object<T: Serialize>(value: &T) -> Result<Map<String, Value>, AuthError> {
    match serde_json::to_value(value)
        .map_err(|error| AuthError::Storage(format!("could not encode MongoDB record: {error}")))?
    {
        Value::Object(record) => Ok(record),
        _ => Err(AuthError::Storage("MongoDB record is not an object".into())),
    }
}

fn insert_oauth_secrets(record: &mut Map<String, Value>, account: &OAuthAccount) {
    record.insert("accessToken".into(), json!(account.access_token));
    record.insert("refreshToken".into(), json!(account.refresh_token));
    record.insert("idToken".into(), json!(account.id_token));
    record.insert("password".into(), json!(account.password));
}

fn optional_string(value: Option<Value>, field: &str) -> Result<Option<String>, AuthError> {
    match value {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) | None => Ok(None),
        _ => Err(AuthError::Storage(format!(
            "invalid MongoDB account row: {field}"
        ))),
    }
}

fn add_transient_defaults(model: &str, record: &mut Map<String, Value>) {
    match model {
        "user" => {
            insert_default(record, "username", Value::Null);
            insert_default(record, "displayUsername", Value::Null);
            insert_default(record, "role", json!("user"));
            insert_default(record, "isAnonymous", json!(false));
            insert_default(record, "banned", json!(false));
            insert_default(record, "banReason", Value::Null);
            insert_default(record, "banExpires", Value::Null);
            record.remove("twoFactorEnabled");
        }
        "session" => {
            insert_default(record, "impersonatedBy", Value::Null);
        }
        _ => {}
    }
}

fn insert_default(record: &mut Map<String, Value>, field: &str, value: Value) {
    record.entry(field).or_insert(value);
}
