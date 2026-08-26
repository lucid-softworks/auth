use crate::{
    AdapterSchemaOptions, AdditionalField, AdditionalFieldType, AuthConfig, AuthSchemaCatalog,
    AuthUser, PluginSchemaTable, ResolvedAdapterSchema,
};
use chrono::Utc;
use serde_json::{Map, Value, json};
use std::sync::Arc;
use uuid::Uuid;

fn physical_schema() -> super::super::physical_schema::PostgresPhysicalSchema {
    let mut config = AuthConfig::new([29; 32]).unwrap();
    config.user.model_name = Some("tenant\"users".into());
    config.user.fields.email = Some("mail address".into());
    let user = PluginSchemaTable::new("user")
        .field(
            "role",
            AdditionalField::new(AdditionalFieldType::String)
                .optional()
                .field_name("admin role"),
        )
        .field(
            "banned",
            AdditionalField::new(AdditionalFieldType::Boolean)
                .optional()
                .field_name("is banned"),
        )
        .field(
            "banReason",
            AdditionalField::new(AdditionalFieldType::String).optional(),
        )
        .field(
            "banExpires",
            AdditionalField::new(AdditionalFieldType::Date).optional(),
        )
        .field(
            "isAnonymous",
            AdditionalField::new(AdditionalFieldType::Boolean).optional(),
        )
        .field(
            "tenantCode",
            AdditionalField::new(AdditionalFieldType::String)
                .optional()
                .field_name("tenant code"),
        );
    let catalog = Arc::new(AuthSchemaCatalog::build(&config, [user]).unwrap());
    let resolved = ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
    super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap()
}

#[test]
fn nullable_plugin_fields_decode_to_domain_defaults() {
    let physical = physical_schema();
    let model = physical.model("user").unwrap();
    let now = Utc::now();
    let mut values = Map::from_iter([
        ("id".into(), json!("custom-user-id")),
        ("name".into(), json!("Ada")),
        ("email".into(), json!("ada@example.com")),
        ("emailVerified".into(), json!(false)),
        ("image".into(), Value::Null),
        ("createdAt".into(), json!(now.to_rfc3339())),
        ("updatedAt".into(), json!(now.to_rfc3339())),
        ("role".into(), Value::Null),
        ("banned".into(), Value::Null),
        ("banReason".into(), Value::Null),
        ("banExpires".into(), Value::Null),
        ("isAnonymous".into(), Value::Null),
        ("tenantCode".into(), json!("blue")),
    ]);
    for field in model.logical_fields() {
        values.entry(field.to_owned()).or_insert(Value::Null);
    }

    let user = super::super::rows::decode_user_values(&model, values).unwrap();
    assert_eq!(user.id, "custom-user-id");
    assert_eq!(user.role, "user");
    assert!(!user.banned);
    assert!(!user.is_anonymous);
    assert_eq!(user.ban_reason, None);
    assert_eq!(user.ban_expires, None);
    assert_eq!(user.additional_fields["tenantCode"], json!("blue"));
}

#[test]
fn user_insert_uses_catalog_identifiers_and_individual_dynamic_columns() {
    let physical = physical_schema();
    let model = physical.model("user").unwrap();
    let now = Utc::now();
    let mut additional_fields = Map::new();
    additional_fields.insert("tenantCode".into(), json!("blue"));
    additional_fields.insert("undeclared".into(), json!("omitted"));
    let user = AuthUser {
        id: Uuid::nil().to_string(),
        username: None,
        display_username: None,
        name: "Ada".into(),
        email: "ada@example.com".into(),
        email_verified: false,
        image: None,
        additional_fields,
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    };
    let writes = super::user_writes(
        &model,
        &user,
        &super::super::rows::explicit_id(user.id.clone()),
    )
    .unwrap();
    let query = super::super::rows::insert_query(&model, writes);
    assert!(query.sql().contains("INSERT INTO \"tenant\"\"users\""));
    assert!(query.sql().contains("\"mail address\""));
    assert!(query.sql().contains("\"tenant code\""));
    assert!(!query.sql().contains("additional_fields"));
    assert!(!query.sql().contains("undeclared"));
    assert!(!query.sql().contains("ada@example.com"));
}
