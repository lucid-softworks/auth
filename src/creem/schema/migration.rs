use super::{ResolvedCreemSchema, SUBSCRIPTION_FIELDS};

pub(super) fn render(schema: &ResolvedCreemSchema) -> String {
    let Some(subscription) = schema.subscription() else {
        return String::new();
    };
    let mut sql = format!(
        "CREATE TABLE IF NOT EXISTS {} (\n    \"id\" UUID PRIMARY KEY",
        subscription.table()
    );
    for (logical, _, definition) in SUBSCRIPTION_FIELDS {
        sql.push_str(&format!(
            ",\n    {} {}",
            subscription.column(logical),
            definition
        ));
    }
    sql.push_str("\n);\n");
    sql
}

#[cfg(test)]
mod tests {
    use crate::creem::schema::migration;
    use crate::creem::{CreemModelSchema, CreemSchema};
    use std::collections::BTreeMap;

    #[test]
    fn migration_is_idempotent_and_has_no_extra_constraints_or_order_fields() {
        let migration = migration(&CreemSchema::default(), true).unwrap();
        assert!(
            migration
                .sql
                .starts_with("CREATE TABLE IF NOT EXISTS \"lucid_auth_creem_subscriptions\"")
        );
        assert!(migration.sql.contains("\"reference_id\" TEXT NOT NULL"));
        assert!(
            migration
                .sql
                .contains("\"status\" TEXT NOT NULL DEFAULT 'pending'")
        );
        assert!(!migration.sql.contains("UNIQUE"));
        assert!(!migration.sql.contains("REFERENCES"));
        assert!(!migration.sql.contains("CREATE INDEX"));
        assert!(!migration.sql.contains("created_at"));
        assert!(!migration.sql.contains("updated_at"));
    }

    #[test]
    fn table_and_every_known_field_are_remappable() {
        let mut fields = BTreeMap::new();
        for (logical, _, _) in super::SUBSCRIPTION_FIELDS {
            fields.insert((*logical).to_owned(), format!("mapped_{logical}"));
        }
        let mut schema = CreemSchema::default();
        schema.insert_model(
            "creem_subscription",
            CreemModelSchema {
                model_name: Some("billing rows".into()),
                fields,
            },
        );
        let sql = migration(&schema, true).unwrap().sql;
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS \"billing rows\""));
        for (logical, _, _) in super::SUBSCRIPTION_FIELDS {
            assert!(sql.contains(&format!("\"mapped_{logical}\"")));
        }
    }
}
