use super::{AuthSchemaCatalog, ResolvedDatabaseIndex};
use crate::AdditionalFieldSet;
use indexmap::IndexMap;

/// Non-plural physical schema produced by Better Auth's generic `getSchema` path.
#[derive(Debug, Clone)]
pub struct GenericDatabaseSchema {
    tables: IndexMap<String, GenericSchemaTable>,
}

/// One physical generic-schema table after logical aliases are merged.
#[derive(Debug, Clone)]
pub struct GenericSchemaTable {
    pub model_name: String,
    pub id_type: super::DatabaseIdType,
    pub logical_sources: Vec<String>,
    pub fields: AdditionalFieldSet,
    pub indexes: Vec<ResolvedDatabaseIndex>,
    pub disable_migrations: bool,
    pub order: Option<u32>,
}

impl GenericDatabaseSchema {
    pub fn from_catalog(catalog: &AuthSchemaCatalog) -> Self {
        let mut tables = IndexMap::<String, GenericSchemaTable>::new();
        for (logical, source) in catalog.tables() {
            let table =
                tables
                    .entry(source.model_name.clone())
                    .or_insert_with(|| GenericSchemaTable {
                        model_name: source.model_name.clone(),
                        id_type: source.id_type,
                        logical_sources: Vec::new(),
                        fields: AdditionalFieldSet::new(),
                        indexes: Vec::new(),
                        disable_migrations: false,
                        order: source.order,
                    });
            table.logical_sources.push(logical.clone());
            table.id_type = source.id_type;
            for (logical_field, source_field) in &source.fields {
                let physical_field = source_field
                    .field_name
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .unwrap_or(logical_field);
                let mut field = source_field.clone();
                if let Some(reference) = &mut field.references
                    && let Some(target) = catalog.table(&reference.model)
                {
                    reference.model.clone_from(&target.model_name);
                }
                table.fields.insert(physical_field.into(), field);
            }
            table.disable_migrations |= source.disable_migrations;
        }
        for (physical, table) in &mut tables {
            if let Some(indexes) = catalog.indexes_by_table().get(physical) {
                table.indexes.extend(indexes.clone());
            }
        }
        Self { tables }
    }

    pub fn tables(&self) -> &IndexMap<String, GenericSchemaTable> {
        &self.tables
    }

    pub fn table(&self, physical_name: &str) -> Option<&GenericSchemaTable> {
        self.tables.get(physical_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AdditionalField, AdditionalFieldReference, AdditionalFieldType,
        AuthConfig, PluginSchemaTable, ResolvedAdapterSchema,
    };
    use std::sync::Arc;

    #[test]
    fn merges_nonplural_aliases_with_sticky_disable_and_later_fields() {
        let mut config = AuthConfig::new([25; 32]).unwrap();
        config.user.model_name = Some("person".into());
        let catalog = AuthSchemaCatalog::build(
            &config,
            [
                PluginSchemaTable::new("first")
                    .model_name("shared")
                    .field(
                        "value",
                        AdditionalField::new(AdditionalFieldType::String).field_name("stored"),
                    )
                    .field(
                        "owner",
                        AdditionalField::new(AdditionalFieldType::String).references(
                            AdditionalFieldReference {
                                model: "user".into(),
                                field: "id".into(),
                                on_delete: None,
                            },
                        ),
                    )
                    .disable_migration(true),
                PluginSchemaTable::new("second")
                    .model_name("shared")
                    .field(
                        "replacement",
                        AdditionalField::new(AdditionalFieldType::Number).field_name("stored"),
                    )
                    .field("extra", AdditionalField::new(AdditionalFieldType::Boolean)),
            ],
        )
        .unwrap();
        let generic = GenericDatabaseSchema::from_catalog(&catalog);
        let shared = generic.table("shared").unwrap();
        assert_eq!(shared.logical_sources, ["first", "second"]);
        assert!(shared.disable_migrations);
        assert_eq!(
            shared.fields["stored"].field_type,
            AdditionalFieldType::Number
        );
        assert_eq!(
            shared.fields["owner"].references.as_ref().unwrap().model,
            "person"
        );
        assert_eq!(
            shared.fields.keys().map(String::as_str).collect::<Vec<_>>(),
            ["stored", "owner", "extra"]
        );
        assert_eq!(generic.table("person").unwrap().order, Some(1));

        let plural = ResolvedAdapterSchema::new(
            Arc::new(catalog),
            AdapterSchemaOptions { use_plural: true },
        )
        .unwrap();
        assert_eq!(plural.model_name("first").unwrap(), "shareds");
        assert!(generic.table("shareds").is_none());
    }

    #[test]
    fn keeps_field_indexes_on_fields_instead_of_table_indexes() {
        let config = AuthConfig::new([26; 32]).unwrap();
        let catalog = AuthSchemaCatalog::build(
            &config,
            [PluginSchemaTable::new("indexed").field(
                "lookup",
                AdditionalField::new(AdditionalFieldType::String).index(true),
            )],
        )
        .unwrap();

        let generic = GenericDatabaseSchema::from_catalog(&catalog);
        let indexed = generic.table("indexed").unwrap();

        assert!(indexed.fields["lookup"].index);
        assert!(indexed.indexes.is_empty());
    }
}
