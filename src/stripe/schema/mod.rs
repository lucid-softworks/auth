use crate::{AdditionalField, AdditionalFieldType, PluginSchemaTable};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StripeModelSchema {
    pub model_name: Option<String>,
    /// Better Auth field name to adapter column name.
    pub fields: BTreeMap<String, String>,
}

impl StripeModelSchema {
    pub fn is_empty(&self) -> bool {
        self.model_name.is_none() && self.fields.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StripeSchema {
    pub user: StripeModelSchema,
    pub organization: StripeModelSchema,
    pub subscription: StripeModelSchema,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StripeSchemaError {
    #[error("unknown Stripe schema field `{field}` on `{model}`")]
    UnknownField { model: &'static str, field: String },
    #[error("invalid Stripe schema {kind} identifier `{identifier}`: {reason}")]
    InvalidIdentifier {
        kind: &'static str,
        identifier: String,
        reason: &'static str,
    },
    #[error("duplicate Stripe schema identifier `{identifier}` on `{model}`")]
    DuplicateIdentifier {
        model: &'static str,
        identifier: String,
    },
}

pub fn schema_tables(
    schema: &StripeSchema,
    subscriptions_enabled: bool,
    organization_enabled: bool,
) -> Vec<PluginSchemaTable> {
    let mut tables = Vec::new();
    if subscriptions_enabled {
        tables.push(subscription_schema_table(schema));
    }
    tables.push(customer_schema_table("user", &schema.user));
    if organization_enabled {
        tables.push(customer_schema_table("organization", &schema.organization));
    }
    tables
}

fn subscription_schema_table(schema: &StripeSchema) -> PluginSchemaTable {
    let config = &schema.subscription;
    let mut table = configured_table("subscription", config);
    for (logical, field) in [
        ("plan", AdditionalField::new(AdditionalFieldType::String)),
        (
            "referenceId",
            AdditionalField::new(AdditionalFieldType::String),
        ),
        ("stripeCustomerId", optional(AdditionalFieldType::String)),
        (
            "stripeSubscriptionId",
            optional(AdditionalFieldType::String),
        ),
        (
            "status",
            AdditionalField::new(AdditionalFieldType::String)
                .default_value(serde_json::json!("incomplete")),
        ),
        ("periodStart", optional(AdditionalFieldType::Date)),
        ("periodEnd", optional(AdditionalFieldType::Date)),
        ("trialStart", optional(AdditionalFieldType::Date)),
        ("trialEnd", optional(AdditionalFieldType::Date)),
        (
            "cancelAtPeriodEnd",
            optional(AdditionalFieldType::Boolean).default_value(serde_json::json!(false)),
        ),
        ("cancelAt", optional(AdditionalFieldType::Date)),
        ("canceledAt", optional(AdditionalFieldType::Date)),
        ("endedAt", optional(AdditionalFieldType::Date)),
        ("seats", optional(AdditionalFieldType::Number)),
        ("billingInterval", optional(AdditionalFieldType::String)),
        ("stripeScheduleId", optional(AdditionalFieldType::String)),
    ] {
        table = table.field(logical, configured_field(logical, field, config));
    }
    table
}

fn customer_schema_table(logical: &'static str, config: &StripeModelSchema) -> PluginSchemaTable {
    configured_table(logical, config).field(
        "stripeCustomerId",
        configured_field(
            "stripeCustomerId",
            AdditionalField::new(AdditionalFieldType::String).optional(),
            config,
        ),
    )
}

fn configured_table(logical: &'static str, config: &StripeModelSchema) -> PluginSchemaTable {
    let table = PluginSchemaTable::new(logical);
    match config.model_name.as_deref().filter(|name| !name.is_empty()) {
        Some(name) => table.model_name(name),
        None => table,
    }
}

fn configured_field(
    logical: &'static str,
    field: AdditionalField,
    config: &StripeModelSchema,
) -> AdditionalField {
    match config.fields.get(logical).filter(|name| !name.is_empty()) {
        Some(name) => field.field_name(name),
        None => field,
    }
}

fn optional(field_type: AdditionalFieldType) -> AdditionalField {
    AdditionalField::new(field_type).optional()
}

#[cfg(test)]
mod catalog_tests {
    use super::*;

    #[test]
    fn exact_conditional_order_shape_and_truthy_remaps() {
        let mut schema = StripeSchema::default();
        schema.user.model_name = Some("person".into());
        schema
            .user
            .fields
            .insert("stripeCustomerId".into(), "".into());
        schema
            .subscription
            .fields
            .insert("referenceId".into(), "owner".into());
        let tables = schema_tables(&schema, true, true);
        assert_eq!(
            tables
                .iter()
                .map(|table| table.logical_name.as_str())
                .collect::<Vec<_>>(),
            ["subscription", "user", "organization"]
        );
        assert_eq!(tables[1].model_name.as_deref(), Some("person"));
        assert_eq!(tables[1].fields["stripeCustomerId"].field_name, None);
        assert_eq!(
            tables[0].fields["referenceId"].field_name.as_deref(),
            Some("owner")
        );
        assert_eq!(
            tables[0]
                .fields
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "plan",
                "referenceId",
                "stripeCustomerId",
                "stripeSubscriptionId",
                "status",
                "periodStart",
                "periodEnd",
                "trialStart",
                "trialEnd",
                "cancelAtPeriodEnd",
                "cancelAt",
                "canceledAt",
                "endedAt",
                "seats",
                "billingInterval",
                "stripeScheduleId",
            ]
        );
        assert!(!tables[0].fields["referenceId"].index);
        assert!(tables[0].fields["stripeCustomerId"].input);
    }
}
