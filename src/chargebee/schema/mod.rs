mod migration;

use crate::{
    AdditionalField, AdditionalFieldType, DatabaseModel, PluginMigration, PluginSchemaField,
};

pub(crate) const SUBSCRIPTION_TABLE: &str = "lucid_auth_chargebee_subscriptions";
pub(crate) const ITEM_TABLE: &str = "lucid_auth_chargebee_subscription_items";
pub(crate) const ORGANIZATION_TABLE: &str = "lucid_auth_organizations";
pub(crate) const CUSTOMER_FIELD: &str = "chargebeeCustomerId";
pub(crate) const ORGANIZATION_CUSTOMER_COLUMN: &str = "chargebee_customer_id";

/// The exact conditional customer field contributed by 1.2.0.
pub fn schema_fields(organization_enabled: bool) -> Vec<PluginSchemaField> {
    let model = if organization_enabled {
        DatabaseModel::Organization
    } else {
        DatabaseModel::User
    };
    vec![PluginSchemaField::new(
        model,
        CUSTOMER_FIELD,
        AdditionalField::new(AdditionalFieldType::String)
            .optional()
            .unique(true)
            .field_name(if organization_enabled {
                ORGANIZATION_CUSTOMER_COLUMN
            } else {
                CUSTOMER_FIELD
            }),
    )]
}

/// One deterministic migration for the enabled 1.2.0 schema shape.
pub fn migration(subscriptions_enabled: bool, organization_enabled: bool) -> PluginMigration {
    let customer = if organization_enabled {
        "organization"
    } else {
        "user"
    };
    let subscriptions = if subscriptions_enabled {
        "subscriptions"
    } else {
        "customers"
    };
    PluginMigration::owned(
        format!("chargebee-better-auth-1-2-0-{customer}-{subscriptions}"),
        "Chargebee Better Auth 1.2.0 conditional schema",
        migration::render(subscriptions_enabled, organization_enabled),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customer_field_switches_between_user_and_organization() {
        let user = schema_fields(false);
        assert_eq!(user.len(), 1);
        assert_eq!(user[0].model, DatabaseModel::User);
        assert_eq!(user[0].name, CUSTOMER_FIELD);
        assert!(user[0].field.unique);
        assert!(!user[0].field.required);

        let organization = schema_fields(true);
        assert_eq!(organization.len(), 1);
        assert_eq!(organization[0].model, DatabaseModel::Organization);
        assert_eq!(
            organization[0].field.field_name.as_deref(),
            Some(ORGANIZATION_CUSTOMER_COLUMN)
        );
    }

    #[test]
    fn every_conditional_shape_has_a_distinct_migration() {
        let shapes = [
            migration(false, false),
            migration(true, false),
            migration(false, true),
            migration(true, true),
        ];
        for (index, shape) in shapes.iter().enumerate() {
            assert!(
                shapes
                    .iter()
                    .enumerate()
                    .all(|(other, candidate)| other == index || candidate.id != shape.id)
            );
        }
    }
}
