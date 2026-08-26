use crate::{AdditionalFieldSet, AuthConfig, AuthError, DatabaseModel, PluginSchemaTable};
use std::collections::BTreeMap;

pub(super) fn additional_schema_fields(
    config: &AuthConfig,
    plugin_tables: &[PluginSchemaTable],
) -> Result<BTreeMap<DatabaseModel, AdditionalFieldSet>, AuthError> {
    let mut schema = BTreeMap::from([
        (DatabaseModel::User, AdditionalFieldSet::new()),
        (DatabaseModel::Session, AdditionalFieldSet::new()),
        (DatabaseModel::Account, AdditionalFieldSet::new()),
        (DatabaseModel::Verification, AdditionalFieldSet::new()),
        (DatabaseModel::Organization, AdditionalFieldSet::new()),
    ]);
    for contribution in plugin_tables {
        let model = match contribution.logical_name.as_str() {
            "user" => Some(DatabaseModel::User),
            "session" => Some(DatabaseModel::Session),
            "account" => Some(DatabaseModel::Account),
            "verification" => Some(DatabaseModel::Verification),
            "organization" => Some(DatabaseModel::Organization),
            _ => None,
        };
        if let Some(model) = model {
            let fields = schema
                .get_mut(&model)
                .expect("every supported service model has a schema field set");
            fields.extend(
                contribution
                    .fields
                    .iter()
                    .filter(|(name, _)| !is_typed_runtime_field(model, name.as_str()))
                    .map(|(name, field)| (name.clone(), field.clone())),
            );
        }
    }
    for (model, fields) in [
        (DatabaseModel::User, &config.user.additional_fields),
        (DatabaseModel::Session, &config.session.additional_fields),
        (DatabaseModel::Account, &config.account.additional_fields),
        (
            DatabaseModel::Verification,
            &config.verification.additional_fields,
        ),
    ] {
        crate::additional_fields::validate_field_names(
            model.as_str(),
            fields,
            crate::additional_fields::reserved_field_names(model),
        )?;
        schema
            .get_mut(&model)
            .expect("every supported service model has a schema field set")
            .extend(fields.clone());
    }
    Ok(schema)
}

fn is_typed_runtime_field(model: DatabaseModel, field: &str) -> bool {
    match model {
        DatabaseModel::User => matches!(
            field,
            "username"
                | "displayUsername"
                | "role"
                | "banned"
                | "banReason"
                | "banExpires"
                | "isAnonymous"
                | "twoFactorEnabled"
        ),
        DatabaseModel::Session => field == "impersonatedBy",
        DatabaseModel::Account | DatabaseModel::Verification | DatabaseModel::Organization => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdditionalField, AdditionalFieldType};

    #[test]
    fn typed_plugin_fields_stay_out_of_flattened_additional_values() {
        let config = AuthConfig::new([7; 32]).unwrap();
        let tables = vec![
            PluginSchemaTable::new("user")
                .field(
                    "isAnonymous",
                    AdditionalField::new(AdditionalFieldType::Boolean),
                )
                .field(
                    "lastLoginMethod",
                    AdditionalField::new(AdditionalFieldType::String),
                ),
            PluginSchemaTable::new("session")
                .field(
                    "impersonatedBy",
                    AdditionalField::new(AdditionalFieldType::String),
                )
                .field(
                    "activeOrganizationId",
                    AdditionalField::new(AdditionalFieldType::String),
                ),
        ];

        let fields = additional_schema_fields(&config, &tables).unwrap();

        assert!(!fields[&DatabaseModel::User].contains_key("isAnonymous"));
        assert!(fields[&DatabaseModel::User].contains_key("lastLoginMethod"));
        assert!(!fields[&DatabaseModel::Session].contains_key("impersonatedBy"));
        assert!(fields[&DatabaseModel::Session].contains_key("activeOrganizationId"));
    }
}
