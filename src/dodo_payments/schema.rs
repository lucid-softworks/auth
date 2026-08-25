use crate::{
    AdditionalField, AdditionalFieldType, DatabaseModel, PluginMigration, PluginSchemaField,
};
use std::borrow::Cow;

/// Dodo contributes one optional, server-owned field and no plugin table.
pub fn dodo_user_schema_field() -> PluginSchemaField {
    PluginSchemaField::new(
        DatabaseModel::User,
        "dodoCustomerId",
        AdditionalField::new(AdditionalFieldType::String)
            .optional()
            .input(false),
    )
}

pub fn dodo_payments_migrations() -> Cow<'static, [PluginMigration]> {
    Cow::Borrowed(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_exactly_one_non_input_optional_user_field() {
        let field = dodo_user_schema_field();
        assert_eq!(field.model, DatabaseModel::User);
        assert_eq!(field.name, "dodoCustomerId");
        assert!(!field.field.required);
        assert!(!field.field.input);
        assert!(field.field.returned);
        assert!(!field.field.has_default());
        assert!(dodo_payments_migrations().is_empty());
    }
}
