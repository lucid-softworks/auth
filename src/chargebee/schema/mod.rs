use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldReference, AdditionalFieldType,
    PluginSchemaTable,
};
use serde_json::json;

pub(crate) const CUSTOMER_FIELD: &str = "chargebeeCustomerId";

/// The exact conditional schema contributed by 1.2.0.
pub fn schema_tables(
    subscriptions_enabled: bool,
    organization_enabled: bool,
) -> Vec<PluginSchemaTable> {
    let model = if organization_enabled {
        "organization"
    } else {
        "user"
    };
    let customer = customer_table(model);
    if !subscriptions_enabled {
        return vec![customer];
    }
    let subscription = subscription_table();
    let item = subscription_item_table();
    if organization_enabled {
        vec![subscription, item, customer]
    } else {
        vec![customer, subscription, item]
    }
}

fn customer_table(model: &'static str) -> PluginSchemaTable {
    PluginSchemaTable::new(model).field(
        CUSTOMER_FIELD,
        AdditionalField::new(AdditionalFieldType::String)
            .optional()
            .unique(true),
    )
}

fn subscription_table() -> PluginSchemaTable {
    PluginSchemaTable::new("subscription")
        .field(
            "referenceId",
            AdditionalField::new(AdditionalFieldType::String),
        )
        .field("chargebeeCustomerId", optional(AdditionalFieldType::String))
        .field(
            "chargebeeSubscriptionId",
            optional(AdditionalFieldType::String).unique(true),
        )
        .field(
            "status",
            optional(AdditionalFieldType::String).default_value(json!("future")),
        )
        .field("periodStart", optional(AdditionalFieldType::Date))
        .field("periodEnd", optional(AdditionalFieldType::Date))
        .field("trialStart", optional(AdditionalFieldType::Date))
        .field("trialEnd", optional(AdditionalFieldType::Date))
        .field("canceledAt", optional(AdditionalFieldType::Date))
        .field("seats", optional(AdditionalFieldType::Number))
        .field("metadata", optional(AdditionalFieldType::String))
}

fn subscription_item_table() -> PluginSchemaTable {
    PluginSchemaTable::new("subscriptionItem")
        .field(
            "subscriptionId",
            AdditionalField::new(AdditionalFieldType::String).references(
                AdditionalFieldReference {
                    model: "subscription".into(),
                    field: "id".into(),
                    on_delete: Some(AdditionalFieldOnDelete::Cascade),
                },
            ),
        )
        .field(
            "itemPriceId",
            AdditionalField::new(AdditionalFieldType::String),
        )
        .field(
            "itemType",
            AdditionalField::new(AdditionalFieldType::String),
        )
        .field(
            "quantity",
            AdditionalField::new(AdditionalFieldType::Number),
        )
        .field("unitPrice", optional(AdditionalFieldType::Number))
        .field("amount", optional(AdditionalFieldType::Number))
}

fn optional(field_type: AdditionalFieldType) -> AdditionalField {
    AdditionalField::new(field_type).optional()
}

/// One deterministic migration for the enabled 1.2.0 schema shape.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customer_field_switches_between_user_and_organization() {
        let user = schema_tables(false, false);
        assert_eq!(user.len(), 1);
        assert_eq!(user[0].logical_name, "user");
        assert!(user[0].fields[CUSTOMER_FIELD].unique);
        assert!(!user[0].fields[CUSTOMER_FIELD].required);

        let organization = schema_tables(false, true);
        assert_eq!(organization.len(), 1);
        assert_eq!(organization[0].logical_name, "organization");
        assert_eq!(organization[0].fields[CUSTOMER_FIELD].field_name, None);
    }

    #[test]
    fn subscription_tables_have_exact_conditional_order_and_shape() {
        let user = schema_tables(true, false);
        assert_eq!(
            user.iter()
                .map(|table| table.logical_name.as_str())
                .collect::<Vec<_>>(),
            ["user", "subscription", "subscriptionItem"]
        );
        let organization = schema_tables(true, true);
        assert_eq!(
            organization
                .iter()
                .map(|table| table.logical_name.as_str())
                .collect::<Vec<_>>(),
            ["subscription", "subscriptionItem", "organization"]
        );
        assert_eq!(
            organization[0]
                .fields
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "referenceId",
                "chargebeeCustomerId",
                "chargebeeSubscriptionId",
                "status",
                "periodStart",
                "periodEnd",
                "trialStart",
                "trialEnd",
                "canceledAt",
                "seats",
                "metadata",
            ]
        );
        assert!(!organization[1].fields["subscriptionId"].index);
        assert_eq!(
            organization[1].fields["subscriptionId"]
                .references
                .as_ref()
                .unwrap()
                .on_delete,
            Some(AdditionalFieldOnDelete::Cascade)
        );
    }
}
