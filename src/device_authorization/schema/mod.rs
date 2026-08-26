use crate::{AdditionalField, AdditionalFieldType, DatabaseSchemaIndex, PluginSchemaTable};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceAuthorizationModelSchema {
    pub model_name: Option<String>,
    /// Better Auth standalone field name to adapter column name.
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceAuthorizationSchema {
    pub device_code: DeviceAuthorizationModelSchema,
}

pub(crate) fn catalog(schema: &DeviceAuthorizationSchema, oauth_mode: bool) -> PluginSchemaTable {
    let mut table = PluginSchemaTable::new("deviceCode");
    if let Some(model_name) = &schema.device_code.model_name {
        table = table.model_name(model_name.clone());
    }
    for (logical, field_type, required) in [
        ("deviceCode", AdditionalFieldType::String, true),
        ("userCode", AdditionalFieldType::String, true),
        ("userId", AdditionalFieldType::String, false),
        ("expiresAt", AdditionalFieldType::Date, true),
        ("status", AdditionalFieldType::String, true),
        ("lastPolledAt", AdditionalFieldType::Date, false),
        ("pollingInterval", AdditionalFieldType::Number, false),
        ("clientId", AdditionalFieldType::String, false),
        ("scope", AdditionalFieldType::String, false),
    ] {
        table = table.field(
            logical,
            configured_field(schema, logical, field_type, required),
        );
    }
    if oauth_mode {
        table = table
            .field(
                "resources",
                configured_field(schema, "resources", AdditionalFieldType::StringArray, false),
            )
            .field(
                "oauthClientId",
                configured_field(schema, "oauthClientId", AdditionalFieldType::String, false),
            );
    }
    table
        .index(DatabaseSchemaIndex::new(["deviceCode"]).unique(true))
        .index(DatabaseSchemaIndex::new(["userCode"]).unique(true))
}

fn configured_field(
    schema: &DeviceAuthorizationSchema,
    logical: &str,
    field_type: AdditionalFieldType,
    required: bool,
) -> AdditionalField {
    let mut field = AdditionalField::new(field_type);
    if !required {
        field = field.optional();
    }
    if let Some(physical) = schema
        .device_code
        .fields
        .get(logical)
        .filter(|name| !name.is_empty())
    {
        field = field.field_name(physical.clone());
    }
    field
}
