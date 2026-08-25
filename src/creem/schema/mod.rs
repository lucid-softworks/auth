mod migration;
mod resolution;

use crate::{
    AdditionalField, AdditionalFieldType, DatabaseModel, PluginMigration, PluginSchemaField,
};
pub(crate) use resolution::ResolvedCreemSchema;
#[cfg(feature = "postgres")]
pub(crate) use resolution::ResolvedModel;
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const SUBSCRIPTION_FIELDS: &[(&str, &str, &str)] = &[
    ("productId", "product_id", "TEXT NOT NULL"),
    ("referenceId", "reference_id", "TEXT NOT NULL"),
    ("creemCustomerId", "creem_customer_id", "TEXT"),
    ("creemSubscriptionId", "creem_subscription_id", "TEXT"),
    ("creemOrderId", "creem_order_id", "TEXT"),
    ("status", "status", "TEXT NOT NULL DEFAULT 'pending'"),
    ("periodStart", "period_start", "TIMESTAMPTZ"),
    ("periodEnd", "period_end", "TIMESTAMPTZ"),
    (
        "cancelAtPeriodEnd",
        "cancel_at_period_end",
        "BOOLEAN NOT NULL DEFAULT FALSE",
    ),
];

pub(crate) const USER_FIELDS: &[(&str, &str, &str)] = &[
    ("creemCustomerId", "creemCustomerId", "TEXT"),
    ("hadTrial", "hadTrial", "BOOLEAN NOT NULL DEFAULT FALSE"),
];

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
pub fn migration(
    schema: &CreemSchema,
    persist_subscriptions: bool,
) -> Result<PluginMigration, CreemSchemaError> {
    let resolved = ResolvedCreemSchema::new(schema, persist_subscriptions)?;
    Ok(PluginMigration::owned(
        format!("creem-better-auth-1-1-4-schema-{}", resolved.fingerprint()),
        "Creem Better Auth 1.1.4 conditional schema",
        resolved.migration_sql(),
    ))
}

/// Core user fields contributed only while subscription persistence is on.
pub fn user_schema_fields(
    schema: &CreemSchema,
    persist_subscriptions: bool,
) -> Result<Vec<PluginSchemaField>, CreemSchemaError> {
    let resolved = ResolvedCreemSchema::new(schema, persist_subscriptions)?;
    let Some(user) = resolved.user() else {
        return Ok(Vec::new());
    };
    Ok(vec![
        PluginSchemaField::new(
            DatabaseModel::User,
            "creemCustomerId",
            AdditionalField::new(AdditionalFieldType::String)
                .optional()
                .field_name(user.unquoted_column("creemCustomerId")),
        ),
        PluginSchemaField::new(
            DatabaseModel::User,
            "hadTrial",
            AdditionalField::new(AdditionalFieldType::Boolean)
                .optional()
                .default_value(Value::Bool(false))
                .field_name(user.unquoted_column("hadTrial")),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_persistence_has_no_schema_but_rejects_any_mapping() {
        let default = CreemSchema::default();
        assert!(user_schema_fields(&default, false).unwrap().is_empty());
        assert!(migration(&default, false).unwrap().sql.is_empty());

        let mut mapped = CreemSchema::default();
        mapped.insert_model("user", CreemModelSchema::default());
        assert_eq!(
            migration(&mapped, false).unwrap_err(),
            CreemSchemaError::PersistenceDisabled
        );
    }

    #[test]
    fn user_fields_preserve_upstream_input_output_and_default_policy() {
        let fields = user_schema_fields(&CreemSchema::default(), true).unwrap();
        assert_eq!(fields.len(), 2);
        let customer = fields
            .iter()
            .find(|field| field.name == "creemCustomerId")
            .unwrap();
        assert!(!customer.field.required);
        assert!(customer.field.input);
        assert!(customer.field.returned);
        assert!(!customer.field.has_default());
        let trial = fields
            .iter()
            .find(|field| field.name == "hadTrial")
            .unwrap();
        assert!(!trial.field.required);
        assert!(trial.field.input);
        assert!(trial.field.returned);
        assert_eq!(
            trial.field.static_default_value(),
            Some(&Value::Bool(false))
        );
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
        let generated = migration(&schema, true).unwrap();
        assert!(generated.sql.contains("lucid_auth_creem_subscriptions"));
        assert!(generated.sql.contains("\"product_id\" TEXT NOT NULL"));
        assert!(!generated.sql.contains("ignored"));

        schema.insert_model("unknown", CreemModelSchema::default());
        assert_eq!(
            migration(&schema, true).unwrap_err(),
            CreemSchemaError::UnknownModel("unknown".into())
        );
    }
}
