use crate::{AdditionalField, AdditionalFieldType, PluginSchemaTable};

/// Dodo contributes one optional, server-owned field and no plugin table.
pub fn dodo_schema_table() -> PluginSchemaTable {
    PluginSchemaTable::new("user").field(
        "dodoCustomerId",
        AdditionalField::new(AdditionalFieldType::String)
            .optional()
            .input(false),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_exactly_one_non_input_optional_user_field() {
        let table = dodo_schema_table();
        let field = &table.fields["dodoCustomerId"];
        assert_eq!(table.logical_name, "user");
        assert!(!field.required);
        assert!(!field.input);
        assert!(field.returned);
        assert!(!field.has_default());
    }
}
