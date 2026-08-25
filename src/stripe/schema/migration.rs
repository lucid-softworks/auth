use super::{ResolvedStripeSchema, SUBSCRIPTION_FIELDS};

pub(super) fn render(schema: &ResolvedStripeSchema) -> String {
    let mut sql = String::new();
    if let Some(organization) = schema.organization() {
        sql.push_str(&format!(
            "ALTER TABLE IF EXISTS {} ADD COLUMN IF NOT EXISTS {} TEXT;\n",
            organization.table(),
            organization.column("stripeCustomerId")
        ));
    }
    if let Some(subscription) = schema.subscription() {
        sql.push_str(&format!(
            "CREATE TABLE IF NOT EXISTS {} (\n    \"id\" UUID PRIMARY KEY",
            subscription.table()
        ));
        for (logical, _, definition) in SUBSCRIPTION_FIELDS {
            sql.push_str(&format!(
                ",\n    {} {}",
                subscription.column(logical),
                definition
            ));
        }
        sql.push_str("\n);\n");
        sql.push_str(&format!(
            "CREATE INDEX IF NOT EXISTS {} ON {} ({});\n",
            index_name(schema.fingerprint(), "reference"),
            subscription.table(),
            subscription.column("referenceId")
        ));
        sql.push_str(&format!(
            "CREATE INDEX IF NOT EXISTS {} ON {} ({});\n",
            index_name(schema.fingerprint(), "stripe_subscription"),
            subscription.table(),
            subscription.column("stripeSubscriptionId")
        ));
    }
    sql
}

fn index_name(fingerprint: &str, suffix: &str) -> String {
    format!("\"lucid_auth_stripe_{fingerprint}_{suffix}_idx\"")
}

#[cfg(test)]
mod tests {
    use crate::stripe::schema::{ResolvedStripeSchema, StripeModelSchema, StripeSchema};
    use std::collections::BTreeMap;

    #[test]
    fn conditional_schema_matches_enabled_features() {
        let disabled = ResolvedStripeSchema::new(&StripeSchema::default(), false, false).unwrap();
        let disabled_sql = disabled.migration_sql();
        assert!(disabled_sql.is_empty());
        assert!(!disabled_sql.contains("lucid_auth_stripe_subscriptions"));
        assert!(!disabled_sql.contains("lucid_auth_organizations"));

        let enabled = ResolvedStripeSchema::new(&StripeSchema::default(), true, true).unwrap();
        let enabled_sql = enabled.migration_sql();
        assert!(enabled_sql.contains("lucid_auth_stripe_subscriptions"));
        assert!(enabled_sql.contains("lucid_auth_organizations"));
        assert!(enabled_sql.contains("\"seats\" DOUBLE PRECISION"));
        assert!(!enabled_sql.contains("limits"));
        assert!(!enabled_sql.contains("group"));
    }

    #[test]
    fn disabled_subscriptions_ignore_their_entire_remap() {
        let schema = StripeSchema {
            subscription: StripeModelSchema {
                model_name: Some("ignored".into()),
                fields: BTreeMap::from([("unknown".into(), "also_ignored".into())]),
            },
            ..StripeSchema::default()
        };
        assert!(ResolvedStripeSchema::new(&schema, false, false).is_ok());
        assert!(ResolvedStripeSchema::new(&schema, true, false).is_err());
    }

    #[test]
    fn every_enabled_model_and_field_is_remappable() {
        let schema = StripeSchema {
            user: StripeModelSchema {
                model_name: Some("auth people".into()),
                fields: BTreeMap::from([("stripeCustomerId".into(), "billing customer".into())]),
            },
            organization: StripeModelSchema {
                model_name: Some("work spaces".into()),
                fields: BTreeMap::from([("stripeCustomerId".into(), "billing customer".into())]),
            },
            subscription: StripeModelSchema {
                model_name: Some("billing plans".into()),
                fields: BTreeMap::from([("referenceId".into(), "owner key".into())]),
            },
        };
        let sql = ResolvedStripeSchema::new(&schema, true, true)
            .unwrap()
            .migration_sql();
        assert!(!sql.contains("\"auth people\""));
        assert!(sql.contains("\"work spaces\""));
        assert!(sql.contains("\"billing plans\""));
        assert!(sql.contains("\"owner key\" TEXT NOT NULL"));
    }

    #[test]
    fn each_conditional_shape_has_a_distinct_migration_id() {
        use crate::stripe::schema::migration;

        let schema = StripeSchema::default();
        let webhook = migration(&schema, false, false).unwrap();
        let subscriptions = migration(&schema, true, false).unwrap();
        let organizations = migration(&schema, true, true).unwrap();
        assert_ne!(webhook.id, subscriptions.id);
        assert_ne!(subscriptions.id, organizations.id);
        assert_ne!(webhook.id, organizations.id);
    }
}
