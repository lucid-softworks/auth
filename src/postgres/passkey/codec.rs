use super::super::{PostgresModel, PostgresWrite};
use crate::{AuthError, StoredPasskey};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;

pub(super) fn passkey_writes<'a>(
    model: &'a PostgresModel<'a>,
    passkey: &StoredPasskey,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", json!(passkey.id.to_string())),
        ("userId", json!(passkey.user_id.to_string())),
        ("name", optional_string(passkey.name.clone())),
        ("credentialID", json!(passkey.credential_id)),
        ("publicKey", json!(passkey.public_key)),
        ("counter", json!(passkey.counter)),
        ("deviceType", json!(passkey.device_type)),
        ("backedUp", json!(passkey.backed_up)),
        ("transports", optional_string(passkey.transports.clone())),
        ("aaguid", optional_string(passkey.aaguid.clone())),
        ("createdAt", json!(passkey.created_at.to_rfc3339())),
    ])
}

pub(super) fn decode_passkey(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<StoredPasskey, AuthError> {
    decode_passkey_values(model.decode_all(row)?)
}

fn decode_passkey_values(mut values: Map<String, Value>) -> Result<StoredPasskey, AuthError> {
    use super::super::rows::{
        optional_string_value, required_bool, required_date, required_string, required_uuid,
    };
    let counter = values
        .remove("counter")
        .and_then(|value| value.as_i64())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| invalid("counter"))?;
    Ok(StoredPasskey {
        id: required_uuid(&mut values, "id")?,
        user_id: required_uuid(&mut values, "userId")?,
        name: optional_string_value(&mut values, "name")?,
        credential_id: required_string(&mut values, "credentialID")?,
        public_key: required_string(&mut values, "publicKey")?,
        counter,
        device_type: required_string(&mut values, "deviceType")?,
        backed_up: required_bool(&mut values, "backedUp")?,
        transports: optional_string_value(&mut values, "transports")?,
        aaguid: optional_string_value(&mut values, "aaguid")?,
        created_at: required_date(&mut values, "createdAt")?,
    })
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

fn invalid(field: &str) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL returned an invalid canonical passkey field '{field}'"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AuthConfig, AuthPlugin, AuthSchemaCatalog, PasskeyConfig,
        PasskeyPlugin, ResolvedAdapterSchema,
    };
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    #[test]
    fn official_projection_uses_hostile_remaps_without_legacy_columns() {
        let config = AuthConfig::new([41; 32]).unwrap();
        let mut passkey = PasskeyConfig::default();
        passkey.schema.model_name = Some("passkey\" records".into());
        passkey
            .schema
            .fields
            .insert("credentialID".into(), "credential id".into());
        let plugin = PasskeyPlugin::new(passkey);
        let catalog = Arc::new(AuthSchemaCatalog::build(&config, plugin.schema()).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        let physical =
            super::super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap();
        let model = physical.model("passkey").unwrap();
        assert_eq!(
            model.logical_fields().collect::<Vec<_>>(),
            vec![
                "name",
                "publicKey",
                "userId",
                "credentialID",
                "counter",
                "deviceType",
                "backedUp",
                "transports",
                "createdAt",
                "aaguid",
            ]
        );
        let now = Utc::now();
        let passkey = StoredPasskey {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: None,
            credential_id: "credential".into(),
            public_key: "key".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            aaguid: None,
            created_at: now,
        };
        let query = super::super::super::rows::insert_query(
            &model,
            passkey_writes(&model, &passkey).unwrap(),
        );
        let sql = query.sql();
        assert!(sql.contains("\"passkey\"\" records\"") && sql.contains("\"credential id\""));
        assert!(
            !sql.contains("credential JSON")
                && !sql.contains("updated_at")
                && !sql.contains("lucid_auth_")
        );
    }
}
