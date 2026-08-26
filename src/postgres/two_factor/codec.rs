use super::super::{PostgresModel, PostgresWrite};
use crate::{AuthError, TwoFactorRecord};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;

pub(super) fn two_factor_writes<'a>(
    model: &'a PostgresModel<'a>,
    record: &TwoFactorRecord,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", json!(record.id.to_string())),
        ("userId", json!(record.user_id)),
        ("secret", json!(record.encrypted_secret)),
        ("backupCodes", json!(record.encrypted_backup_codes)),
        ("verified", json!(record.verified)),
        (
            "failedVerificationCount",
            json!(record.failed_verification_count),
        ),
        ("lockedUntil", optional_date(record.locked_until)),
    ])
}

pub(super) fn two_factor_update_writes<'a>(
    model: &'a PostgresModel<'a>,
    record: &TwoFactorRecord,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let values = two_factor_values(record);
    model.encode_fields(
        [
            "secret",
            "backupCodes",
            "verified",
            "failedVerificationCount",
            "lockedUntil",
        ]
        .into_iter()
        .map(|field| (field, values[field].clone())),
    )
}

pub(super) fn decode_two_factor(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<TwoFactorRecord, AuthError> {
    decode_two_factor_values(model.decode_all(row)?)
}

fn decode_two_factor_values(mut values: Map<String, Value>) -> Result<TwoFactorRecord, AuthError> {
    use super::super::rows::{optional_date_value, required_string, required_uuid};
    let verified = optional_bool(&mut values, "verified", true)?;
    let failed_verification_count = optional_u32(&mut values, "failedVerificationCount", 0)?;
    Ok(TwoFactorRecord {
        id: required_uuid(&mut values, "id")?,
        user_id: required_string(&mut values, "userId")?,
        encrypted_secret: required_string(&mut values, "secret")?,
        encrypted_backup_codes: required_string(&mut values, "backupCodes")?,
        verified,
        failed_verification_count,
        locked_until: optional_date_value(&mut values, "lockedUntil")?,
    })
}

fn optional_bool(
    values: &mut Map<String, Value>,
    field: &str,
    default: bool,
) -> Result<bool, AuthError> {
    match values.remove(field) {
        Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(value),
        _ => Err(invalid(field)),
    }
}

fn optional_u32(
    values: &mut Map<String, Value>,
    field: &str,
    default: u32,
) -> Result<u32, AuthError> {
    match values.remove(field) {
        Some(Value::Null) => Ok(default),
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| invalid(field)),
        _ => Err(invalid(field)),
    }
}

fn two_factor_values(record: &TwoFactorRecord) -> Map<String, Value> {
    Map::from_iter([
        ("secret".into(), json!(record.encrypted_secret)),
        ("backupCodes".into(), json!(record.encrypted_backup_codes)),
        ("verified".into(), json!(record.verified)),
        (
            "failedVerificationCount".into(),
            json!(record.failed_verification_count),
        ),
        ("lockedUntil".into(), optional_date(record.locked_until)),
    ])
}

fn optional_date(value: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    value.map_or(Value::Null, |value| json!(value.to_rfc3339()))
}

fn invalid(field: &str) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL returned an invalid canonical two-factor field '{field}'"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AuthConfig, AuthPlugin, AuthSchemaCatalog, MemoryTwoFactorStore,
        ResolvedAdapterSchema, TwoFactorConfig, TwoFactorPlugin,
    };
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    #[test]
    fn official_projection_honors_hostile_remaps_and_has_no_alternate_state() {
        let auth = AuthConfig::new([43; 32]).unwrap();
        let mut config = TwoFactorConfig::default();
        config.schema.two_factor.model_name = Some("two\" factor".into());
        config
            .schema
            .two_factor
            .fields
            .insert("secret".into(), "encrypted secret".into());
        config
            .schema
            .user
            .fields
            .insert("twoFactorEnabled".into(), "two factor enabled".into());
        let plugin = TwoFactorPlugin::new(Arc::new(MemoryTwoFactorStore::default()), config);
        let catalog = Arc::new(AuthSchemaCatalog::build(&auth, plugin.schema()).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        let physical =
            super::super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap();
        let model = physical.model("twoFactor").unwrap();
        assert_eq!(
            model.logical_fields().collect::<Vec<_>>(),
            vec![
                "secret",
                "backupCodes",
                "userId",
                "verified",
                "failedVerificationCount",
                "lockedUntil",
            ]
        );
        let record = TwoFactorRecord {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4().to_string(),
            encrypted_secret: "bound' --".into(),
            encrypted_backup_codes: "codes".into(),
            verified: false,
            failed_verification_count: 0,
            locked_until: Some(Utc::now()),
        };
        let query = super::super::super::rows::insert_query(
            &model,
            two_factor_writes(&model, &record).unwrap(),
        );
        let sql = query.sql();
        assert!(sql.contains("\"two\"\" factor\"") && sql.contains("\"encrypted secret\""));
        assert!(!sql.contains("bound") && !sql.contains("last_totp_counter"));
        let user = physical.model("user").unwrap();
        assert_eq!(
            user.quoted_column("twoFactorEnabled").unwrap(),
            "\"two factor enabled\""
        );
    }

    #[test]
    fn nullable_official_defaults_decode_without_alternate_columns() {
        let id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let record = decode_two_factor_values(Map::from_iter([
            ("id".into(), json!(id.to_string())),
            ("userId".into(), json!(user_id.to_string())),
            ("secret".into(), json!("secret")),
            ("backupCodes".into(), json!("codes")),
            ("verified".into(), Value::Null),
            ("failedVerificationCount".into(), Value::Null),
            ("lockedUntil".into(), Value::Null),
        ]))
        .unwrap();
        assert!(record.verified);
        assert_eq!(record.failed_verification_count, 0);
        assert_eq!(record.locked_until, None);
    }

    #[test]
    fn plugin_absence_does_not_create_an_alternate_model() {
        let auth = AuthConfig::new([44; 32]).unwrap();
        let catalog = Arc::new(AuthSchemaCatalog::build(&auth, []).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        let physical =
            super::super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap();
        assert!(physical.model("twoFactor").is_err());
        assert!(
            physical
                .model("user")
                .unwrap()
                .quoted_column("twoFactorEnabled")
                .is_err()
        );
    }
}
