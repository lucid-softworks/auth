mod migration;
mod resolution;

use crate::{
    AdditionalField, AdditionalFieldType, DatabaseModel, PluginMigration, PluginSchemaField,
};
#[cfg(feature = "postgres")]
pub(crate) use resolution::ResolvedModel;
pub(crate) use resolution::ResolvedStripeSchema;
use std::collections::BTreeMap;

pub(crate) const SUBSCRIPTION_FIELDS: &[(&str, &str, &str)] = &[
    ("plan", "plan", "TEXT NOT NULL"),
    ("referenceId", "reference_id", "TEXT NOT NULL"),
    ("stripeCustomerId", "stripe_customer_id", "TEXT"),
    ("stripeSubscriptionId", "stripe_subscription_id", "TEXT"),
    ("status", "status", "TEXT NOT NULL DEFAULT 'incomplete'"),
    ("periodStart", "period_start", "TIMESTAMPTZ"),
    ("periodEnd", "period_end", "TIMESTAMPTZ"),
    ("trialStart", "trial_start", "TIMESTAMPTZ"),
    ("trialEnd", "trial_end", "TIMESTAMPTZ"),
    (
        "cancelAtPeriodEnd",
        "cancel_at_period_end",
        "BOOLEAN NOT NULL DEFAULT FALSE",
    ),
    ("cancelAt", "cancel_at", "TIMESTAMPTZ"),
    ("canceledAt", "canceled_at", "TIMESTAMPTZ"),
    ("endedAt", "ended_at", "TIMESTAMPTZ"),
    ("seats", "seats", "DOUBLE PRECISION"),
    ("billingInterval", "billing_interval", "TEXT"),
    ("stripeScheduleId", "stripe_schedule_id", "TEXT"),
    ("createdAt", "created_at", "TIMESTAMPTZ NOT NULL"),
    ("updatedAt", "updated_at", "TIMESTAMPTZ NOT NULL"),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StripeModelSchema {
    pub model_name: Option<String>,
    /// Better Auth field name to adapter column name.
    pub fields: BTreeMap<String, String>,
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

pub fn migration(
    schema: &StripeSchema,
    subscriptions_enabled: bool,
    organization_enabled: bool,
) -> Result<PluginMigration, StripeSchemaError> {
    let resolved = ResolvedStripeSchema::new(schema, subscriptions_enabled, organization_enabled)?;
    let id = format!("better-auth-stripe-1-7-1-schema-{}", resolved.fingerprint());
    Ok(PluginMigration::owned(
        id,
        "Better Auth Stripe 1.7.1 conditional schema",
        resolved.migration_sql(),
    ))
}

/// Core user fields use the host adapter's Better Auth additional-field path.
pub fn user_schema_field(schema: &StripeSchema) -> PluginSchemaField {
    let field_name = schema
        .user
        .fields
        .get("stripeCustomerId")
        .cloned()
        .unwrap_or_else(|| "stripeCustomerId".to_owned());
    PluginSchemaField::new(
        DatabaseModel::User,
        "stripeCustomerId",
        AdditionalField::new(AdditionalFieldType::String)
            .optional()
            .input(false)
            .field_name(field_name),
    )
}
