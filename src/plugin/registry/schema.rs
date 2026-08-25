use super::invalid;
use crate::{AdditionalFieldSet, AuthConfig, AuthError, DatabaseModel, PluginSchemaField};
use std::collections::BTreeMap;

pub(super) fn core_schema_fields(
    config: &AuthConfig,
) -> BTreeMap<DatabaseModel, AdditionalFieldSet> {
    BTreeMap::from([
        (DatabaseModel::User, config.user.additional_fields.clone()),
        (
            DatabaseModel::Session,
            config.session.additional_fields.clone(),
        ),
        (
            DatabaseModel::Account,
            config.account.additional_fields.clone(),
        ),
        (
            DatabaseModel::Verification,
            config.verification.additional_fields.clone(),
        ),
        (DatabaseModel::Organization, AdditionalFieldSet::new()),
    ])
}

pub(super) fn merge_schema_fields(
    schema: &mut BTreeMap<DatabaseModel, AdditionalFieldSet>,
    fields: Vec<PluginSchemaField>,
    plugin_id: &str,
) -> Result<(), AuthError> {
    for contribution in fields {
        let model = contribution.model;
        let model_fields = schema
            .get_mut(&model)
            .expect("every Better Auth core model has a schema field set");
        if model_fields
            .insert(contribution.name.clone(), contribution.field)
            .is_some()
        {
            return invalid(format!(
                "plugin '{plugin_id}' schema field '{}.{}' conflicts with an existing field",
                model.as_str(),
                contribution.name
            ));
        }
        crate::additional_fields::validate_field_names(
            model.as_str(),
            model_fields,
            crate::additional_fields::reserved_field_names(model),
        )?;
    }
    Ok(())
}
