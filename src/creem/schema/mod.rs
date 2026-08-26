use crate::{AdditionalField, AdditionalFieldType, PluginSchemaTable};
use serde_json::Value;
use std::collections::BTreeMap;

/// One model/table and its Better Auth field-to-adapter-name remappings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreemModelSchema {
    pub model_name: Option<String>,
    pub fields: BTreeMap<String, String>,
}

/// Creem's map-shaped schema override.
///
/// An empty map means the upstream defaults. Keeping model names in a map is
/// intentional: the pinned JavaScript runtime throws for unknown model keys,
/// which a closed Rust struct could not represent or test.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreemSchema {
    pub models: BTreeMap<String, CreemModelSchema>,
}

impl CreemSchema {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_model(
        &mut self,
        logical_name: impl Into<String>,
        mapping: CreemModelSchema,
    ) -> Option<CreemModelSchema> {
        self.models.insert(logical_name.into(), mapping)
    }

    pub fn model_mut(&mut self, logical_name: impl Into<String>) -> &mut CreemModelSchema {
        self.models.entry(logical_name.into()).or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreemSchemaError {
    #[error("Creem schema remapping requires persistSubscriptions to be enabled")]
    PersistenceDisabled,
    #[error("unknown Creem schema model `{0}`")]
    UnknownModel(String),
    #[error("invalid Creem schema {kind} identifier `{identifier}`: {reason}")]
    InvalidIdentifier {
        kind: &'static str,
        identifier: String,
        reason: &'static str,
    },
}

/// Produces the plugin-owned, deterministic migration for this schema.
/// Core user fields contributed only while subscription persistence is on.
pub fn schema_tables(
    schema: &CreemSchema,
    persist_subscriptions: bool,
) -> Result<Vec<PluginSchemaTable>, CreemSchemaError> {
    if !persist_subscriptions {
        if !schema.is_empty() {
            return Err(CreemSchemaError::PersistenceDisabled);
        }
        return Ok(Vec::new());
    }
    if let Some(unknown) = schema
        .models
        .keys()
        .find(|name| !matches!(name.as_str(), "creem_subscription" | "user"))
    {
        return Err(CreemSchemaError::UnknownModel(unknown.clone()));
    }
    let subscription = schema.models.get("creem_subscription");
    let user = schema.models.get("user");
    let mut subscription_table = configured_table("creem_subscription", subscription);
    for (logical, field) in [
        (
            "productId",
            AdditionalField::new(AdditionalFieldType::String),
        ),
        (
            "referenceId",
            AdditionalField::new(AdditionalFieldType::String),
        ),
        ("creemCustomerId", optional(AdditionalFieldType::String)),
        ("creemSubscriptionId", optional(AdditionalFieldType::String)),
        ("creemOrderId", optional(AdditionalFieldType::String)),
        (
            "status",
            AdditionalField::new(AdditionalFieldType::String)
                .default_value(Value::String("pending".into())),
        ),
        ("periodStart", optional(AdditionalFieldType::Date)),
        ("periodEnd", optional(AdditionalFieldType::Date)),
        (
            "cancelAtPeriodEnd",
            optional(AdditionalFieldType::Boolean).default_value(Value::Bool(false)),
        ),
    ] {
        subscription_table =
            subscription_table.field(logical, configured_field(logical, field, subscription));
    }
    let user_table = configured_table("user", user)
        .field(
            "creemCustomerId",
            configured_field(
                "creemCustomerId",
                optional(AdditionalFieldType::String),
                user,
            ),
        )
        .field(
            "hadTrial",
            configured_field(
                "hadTrial",
                optional(AdditionalFieldType::Boolean).default_value(Value::Bool(false)),
                user,
            ),
        );
    Ok(vec![subscription_table, user_table])
}

fn configured_table(logical: &'static str, config: Option<&CreemModelSchema>) -> PluginSchemaTable {
    let table = PluginSchemaTable::new(logical);
    match config
        .and_then(|config| config.model_name.as_deref())
        .filter(|name| !name.is_empty())
    {
        Some(name) => table.model_name(name),
        None => table,
    }
}

fn configured_field(
    logical: &'static str,
    field: AdditionalField,
    config: Option<&CreemModelSchema>,
) -> AdditionalField {
    match config
        .and_then(|config| config.fields.get(logical))
        .filter(|name| !name.is_empty())
    {
        Some(name) => field.field_name(name),
        None => field,
    }
}

fn optional(field_type: AdditionalFieldType) -> AdditionalField {
    AdditionalField::new(field_type).optional()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_persistence_has_no_schema_but_rejects_any_mapping() {
        let default = CreemSchema::default();
        assert!(schema_tables(&default, false).unwrap().is_empty());
        let mut mapped = CreemSchema::default();
        mapped.insert_model("user", CreemModelSchema::default());
        assert_eq!(
            schema_tables(&mapped, false).unwrap_err(),
            CreemSchemaError::PersistenceDisabled
        );
    }

    #[test]
    fn user_fields_preserve_upstream_input_output_and_default_policy() {
        let tables = schema_tables(&CreemSchema::default(), true).unwrap();
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].logical_name, "creem_subscription");
        let customer = &tables[1].fields["creemCustomerId"];
        assert!(!customer.required);
        assert!(customer.input);
        assert!(customer.returned);
        assert!(!customer.has_default());
        let trial = &tables[1].fields["hadTrial"];
        assert!(!trial.required);
        assert!(trial.input);
        assert!(trial.returned);
        assert_eq!(trial.static_default_value(), Some(&Value::Bool(false)));
    }

    #[test]
    fn unknown_fields_and_empty_names_are_ignored_but_unknown_models_fail() {
        let mut schema = CreemSchema::default();
        schema.insert_model(
            "creem_subscription",
            CreemModelSchema {
                model_name: Some(String::new()),
                fields: BTreeMap::from([
                    ("productId".into(), String::new()),
                    ("notAField".into(), "ignored".into()),
                ]),
            },
        );
        let generated = schema_tables(&schema, true).unwrap();
        assert_eq!(generated[0].model_name, None);
        assert_eq!(generated[0].fields["productId"].field_name, None);
        assert!(!generated[0].fields.contains_key("notAField"));

        schema.insert_model("unknown", CreemModelSchema::default());
        assert_eq!(
            schema_tables(&schema, true).unwrap_err(),
            CreemSchemaError::UnknownModel("unknown".into())
        );
    }
}
