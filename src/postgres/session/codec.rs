use super::super::{PostgresModel, PostgresWrite};
use crate::{AuthError, AuthSession};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;

const CORE_FIELDS: &[&str] = &[
    "id",
    "userId",
    "token",
    "expiresAt",
    "createdAt",
    "updatedAt",
    "ipAddress",
    "userAgent",
    "impersonatedBy",
];

pub(in crate::postgres) fn session_writes<'a>(
    model: &'a PostgresModel<'a>,
    session: &AuthSession,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let mut values = Map::from_iter([
        ("id".into(), json!(session.id.to_string())),
        ("userId".into(), json!(session.user_id.to_string())),
        ("token".into(), json!(session.token)),
        ("expiresAt".into(), json!(session.expires_at.to_rfc3339())),
        ("createdAt".into(), json!(session.created_at.to_rfc3339())),
        ("updatedAt".into(), json!(session.updated_at.to_rfc3339())),
        (
            "ipAddress".into(),
            session
                .ip_address
                .clone()
                .map_or(Value::Null, Value::String),
        ),
        (
            "userAgent".into(),
            session
                .user_agent
                .clone()
                .map_or(Value::Null, Value::String),
        ),
    ]);
    if model.has_field("impersonatedBy") {
        values.insert(
            "impersonatedBy".into(),
            session
                .actor_user_id
                .map(|value| Value::String(value.to_string()))
                .unwrap_or(Value::Null),
        );
    }
    for (logical, value) in &session.additional_fields {
        if CORE_FIELDS.contains(&logical.as_str()) {
            return Err(AuthError::InvalidConfiguration(format!(
                "session additional field '{logical}' collides with a canonical Better Auth field"
            )));
        }
        if model.has_field(logical) {
            values.insert(logical.clone(), value.clone());
        }
    }
    model.encode_fields(
        values
            .iter()
            .map(|(logical, value)| (logical.as_str(), value.clone())),
    )
}

pub(in crate::postgres) fn decode_session(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<AuthSession, AuthError> {
    decode_session_values(model, model.decode_all(row)?)
}

pub(super) fn decode_session_values(
    model: &PostgresModel<'_>,
    mut values: Map<String, Value>,
) -> Result<AuthSession, AuthError> {
    use super::super::rows::{
        optional_string_value, required_date, required_string, required_uuid,
    };

    let id = required_uuid(&mut values, "id")?;
    let user_id = required_uuid(&mut values, "userId")?;
    let token = required_string(&mut values, "token")?;
    let expires_at = required_date(&mut values, "expiresAt")?;
    let created_at = required_date(&mut values, "createdAt")?;
    let updated_at = required_date(&mut values, "updatedAt")?;
    let ip_address = optional_string_value(&mut values, "ipAddress")?;
    let user_agent = optional_string_value(&mut values, "userAgent")?;
    let actor_user_id = if model.has_field("impersonatedBy") {
        match optional_string_value(&mut values, "impersonatedBy")? {
            Some(value) => Some(
                uuid::Uuid::parse_str(&value).map_err(|_| invalid_session_row("impersonatedBy"))?,
            ),
            None => None,
        }
    } else {
        None
    };
    Ok(AuthSession {
        id,
        user_id,
        token,
        actor_user_id,
        authentication_method: None,
        expires_at,
        created_at,
        updated_at,
        ip_address,
        user_agent,
        additional_fields: values,
    })
}

fn invalid_session_row(field: &str) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL returned an invalid canonical session field '{field}'"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AdditionalField, AdditionalFieldType, AuthConfig, AuthSchemaCatalog,
        PluginSchemaTable, ResolvedAdapterSchema,
    };
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    fn physical(admin: bool) -> super::super::super::physical_schema::PostgresPhysicalSchema {
        let mut config = AuthConfig::new([31; 32]).unwrap();
        config.session.model_name = Some("session\" records".into());
        config.session.fields.token = Some("bearer token".into());
        config.session.additional_fields.insert(
            "tenantCode".into(),
            AdditionalField::new(AdditionalFieldType::String)
                .optional()
                .field_name("tenant code"),
        );
        let plugins = admin.then(|| {
            PluginSchemaTable::new("session").field(
                "impersonatedBy",
                AdditionalField::new(AdditionalFieldType::String)
                    .optional()
                    .field_name("admin actor"),
            )
        });
        let catalog = Arc::new(AuthSchemaCatalog::build(&config, plugins).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        super::super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap()
    }

    #[test]
    fn codec_uses_remapped_columns_and_never_persists_transient_authentication() {
        let physical = physical(true);
        let model = physical.model("session").unwrap();
        let now = Utc::now();
        let actor = Uuid::new_v4();
        let mut additional_fields = Map::new();
        additional_fields.insert("tenantCode".into(), json!("blue"));
        additional_fields.insert("undeclared".into(), json!("omitted"));
        let session = AuthSession {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token: "secret".into(),
            actor_user_id: Some(actor),
            authentication_method: Some(crate::AuthenticationMethod::Passkey),
            expires_at: now,
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
            additional_fields,
        };
        let writes = session_writes(&model, &session).unwrap();
        let query = super::super::super::rows::insert_query(&model, writes);
        let sql = query.sql();
        assert!(sql.contains("\"session\"\" records\""));
        assert!(sql.contains("\"bearer token\""));
        assert!(sql.contains("\"admin actor\""));
        assert!(sql.contains("\"tenant code\""));
        assert!(!sql.contains("authentication_method"));
        assert!(!sql.contains("additional_fields"));
        assert!(!sql.contains("actor_user_id"));
        assert!(!sql.contains("undeclared"));
    }

    #[test]
    fn decode_without_admin_field_has_no_fabricated_actor_or_authentication_method() {
        let physical = physical(false);
        let model = physical.model("session").unwrap();
        let now = Utc::now();
        let mut values = Map::from_iter([
            ("id".into(), json!(Uuid::new_v4().to_string())),
            ("userId".into(), json!(Uuid::new_v4().to_string())),
            ("token".into(), json!("token")),
            ("expiresAt".into(), json!(now.to_rfc3339())),
            ("createdAt".into(), json!(now.to_rfc3339())),
            ("updatedAt".into(), json!(now.to_rfc3339())),
            ("ipAddress".into(), Value::Null),
            ("userAgent".into(), Value::Null),
            ("tenantCode".into(), json!("blue")),
        ]);
        let session = decode_session_values(&model, std::mem::take(&mut values)).unwrap();
        assert_eq!(session.actor_user_id, None);
        assert_eq!(session.authentication_method, None);
        assert_eq!(session.additional_fields["tenantCode"], json!("blue"));
    }
}
