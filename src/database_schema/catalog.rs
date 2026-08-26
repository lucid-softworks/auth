use crate::{AdditionalField, AdditionalFieldSet, AuthConfig};
use indexmap::IndexMap;
use std::collections::BTreeMap;

pub use super::fingerprint::SchemaFingerprint;

/// Better Auth `schema` remapping for one logical model.
#[derive(Debug, Clone, Default)]
pub struct DatabaseModelSchema {
    pub model_name: Option<String>,
    pub fields: BTreeMap<String, String>,
    pub additional_fields: AdditionalFieldSet,
}

impl DatabaseModelSchema {
    pub fn is_empty(&self) -> bool {
        self.model_name.is_none() && self.fields.is_empty() && self.additional_fields.is_empty()
    }
}

/// One Better Auth table-level index in logical field order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseSchemaIndex {
    pub name: Option<String>,
    pub fields: Vec<String>,
    pub unique: bool,
}

/// Storage type for a model's implicit Better Auth `id` field.
///
/// This describes storage only. ID generation remains the caller's responsibility.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DatabaseIdType {
    #[default]
    Uuid,
    String,
}

impl DatabaseSchemaIndex {
    pub fn new(fields: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            name: None,
            fields: fields.into_iter().map(Into::into).collect(),
            unique: false,
        }
    }

    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn unique(mut self, unique: bool) -> Self {
        self.unique = unique;
        self
    }
}

/// One ordered schema object contributed by a Better Auth plugin.
#[derive(Debug, Clone)]
pub struct PluginSchemaTable {
    pub logical_name: String,
    pub model_name: Option<String>,
    pub id_type: Option<DatabaseIdType>,
    pub fields: AdditionalFieldSet,
    pub indexes: Vec<DatabaseSchemaIndex>,
    pub disable_migration: Option<bool>,
}

impl PluginSchemaTable {
    pub fn new(logical_name: impl Into<String>) -> Self {
        Self {
            logical_name: logical_name.into(),
            model_name: None,
            id_type: None,
            fields: AdditionalFieldSet::new(),
            indexes: Vec::new(),
            disable_migration: None,
        }
    }

    pub fn model_name(mut self, model_name: impl Into<String>) -> Self {
        self.model_name = Some(model_name.into());
        self
    }

    pub fn id_type(mut self, id_type: DatabaseIdType) -> Self {
        self.id_type = Some(id_type);
        self
    }

    pub fn field(mut self, logical_name: impl Into<String>, field: AdditionalField) -> Self {
        self.fields.insert(logical_name.into(), field);
        self
    }

    pub fn index(mut self, index: DatabaseSchemaIndex) -> Self {
        self.indexes.push(index);
        self
    }

    pub fn disable_migration(mut self, disable: bool) -> Self {
        self.disable_migration = Some(disable);
        self
    }
}

/// One final logical table after Better Auth plugin/core/host merging.
#[derive(Debug, Clone)]
pub struct SchemaTable {
    pub model_name: String,
    pub id_type: DatabaseIdType,
    pub fields: AdditionalFieldSet,
    pub indexes: Vec<DatabaseSchemaIndex>,
    pub disable_migrations: bool,
    pub order: Option<u32>,
}

/// Immutable ordered equivalent of Better Auth 1.7.1 `buildAuthTables`.
#[derive(Debug, Clone)]
pub struct AuthSchemaCatalog {
    tables: IndexMap<String, SchemaTable>,
    indexes_by_table: IndexMap<String, Vec<super::ResolvedDatabaseIndex>>,
    field_indexes_by_table: IndexMap<String, Vec<super::ResolvedDatabaseIndex>>,
    fingerprint: SchemaFingerprint,
}

impl AuthSchemaCatalog {
    pub(crate) fn build(
        config: &AuthConfig,
        plugin_tables: impl IntoIterator<Item = PluginSchemaTable>,
    ) -> Result<Self, super::SchemaIndexError> {
        let plugin_tables = accumulate_plugins(plugin_tables);
        let tables = super::core::build_tables(config, plugin_tables);
        let mut catalog = Self {
            tables,
            indexes_by_table: IndexMap::new(),
            field_indexes_by_table: IndexMap::new(),
            fingerprint: SchemaFingerprint(String::new()),
        };
        catalog.indexes_by_table = super::indexes::resolve(&catalog)?;
        catalog.field_indexes_by_table =
            super::indexes::resolve_field_indexes_for_adapter(&catalog, false)?;
        catalog.fingerprint = SchemaFingerprint::from_catalog(&catalog);
        Ok(catalog)
    }

    pub fn tables(&self) -> &IndexMap<String, SchemaTable> {
        &self.tables
    }

    pub fn table(&self, logical_name: &str) -> Option<&SchemaTable> {
        self.tables.get(logical_name)
    }

    pub fn fingerprint(&self) -> &SchemaFingerprint {
        &self.fingerprint
    }

    pub fn indexes_by_table(&self) -> &IndexMap<String, Vec<super::ResolvedDatabaseIndex>> {
        &self.indexes_by_table
    }

    pub fn field_indexes_by_table(&self) -> &IndexMap<String, Vec<super::ResolvedDatabaseIndex>> {
        &self.field_indexes_by_table
    }

    pub fn generic_schema(&self) -> super::GenericDatabaseSchema {
        super::GenericDatabaseSchema::from_catalog(self)
    }
}

fn accumulate_plugins(
    contributions: impl IntoIterator<Item = PluginSchemaTable>,
) -> IndexMap<String, SchemaTable> {
    let mut tables = IndexMap::<String, SchemaTable>::new();
    for contribution in contributions {
        let logical_name = contribution.logical_name;
        let id_type = contribution.id_type;
        let selected_model_name = truthy(contribution.model_name.as_deref())
            .unwrap_or(&logical_name)
            .to_owned();
        let table = tables.entry(logical_name).or_insert_with(|| SchemaTable {
            model_name: selected_model_name.clone(),
            id_type: id_type.unwrap_or_default(),
            fields: AdditionalFieldSet::new(),
            indexes: Vec::new(),
            disable_migrations: false,
            order: None,
        });
        for (logical, field) in contribution.fields {
            table.fields.insert(logical, field);
        }
        for index in contribution.indexes {
            if !table.indexes.iter().any(|existing| existing == &index) {
                table.indexes.push(index);
            }
        }
        table.model_name = selected_model_name;
        if let Some(id_type) = id_type {
            table.id_type = id_type;
        }
        if let Some(disable) = contribution.disable_migration {
            table.disable_migrations = disable;
        }
    }
    tables
}

pub(super) fn truthy(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

pub(crate) fn remap_plugin_table(
    mut table: PluginSchemaTable,
    schema: &DatabaseModelSchema,
    include_additional_fields: bool,
) -> PluginSchemaTable {
    if let Some(model_name) = truthy(schema.model_name.as_deref()) {
        table.model_name = Some(model_name.into());
    }
    for (logical, field) in &mut table.fields {
        if let Some(physical) = truthy(schema.fields.get(logical).map(String::as_str)) {
            field.field_name = Some(physical.into());
        }
    }
    if include_additional_fields {
        table.fields.extend(schema.additional_fields.clone());
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdditionalFieldType, AuthConfig};

    #[test]
    fn plugin_overwrites_preserve_position_and_latest_options() {
        let config = AuthConfig::new([7; 32]).unwrap();
        let catalog = AuthSchemaCatalog::build(
            &config,
            [
                PluginSchemaTable::new("widget")
                    .model_name("first")
                    .id_type(DatabaseIdType::String)
                    .field("a", AdditionalField::new(AdditionalFieldType::String))
                    .field("b", AdditionalField::new(AdditionalFieldType::String))
                    .disable_migration(true),
                PluginSchemaTable::new("widget")
                    .field("a", AdditionalField::new(AdditionalFieldType::Number))
                    .disable_migration(false),
            ],
        )
        .unwrap();
        let table = catalog.table("widget").unwrap();
        assert_eq!(table.model_name, "widget");
        assert_eq!(table.id_type, DatabaseIdType::String);
        assert!(!table.disable_migrations);
        assert_eq!(
            table.fields.keys().map(String::as_str).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(table.fields["a"].field_type, AdditionalFieldType::Number);
    }

    #[test]
    fn plugin_remaps_ignore_empty_and_unknown_entries_and_append_additional_fields() {
        let table = PluginSchemaTable::new("widget")
            .field("known", AdditionalField::new(AdditionalFieldType::String));
        let mut schema = DatabaseModelSchema {
            model_name: Some("widgets".into()),
            fields: BTreeMap::from([
                ("known".into(), "".into()),
                ("unknown".into(), "invented".into()),
            ]),
            additional_fields: AdditionalFieldSet::new(),
        };
        schema.additional_fields.insert(
            "extra".into(),
            AdditionalField::new(AdditionalFieldType::Boolean),
        );
        let table = remap_plugin_table(table, &schema, true);
        assert_eq!(table.model_name.as_deref(), Some("widgets"));
        assert_eq!(table.fields["known"].field_name, None);
        assert!(!table.fields.contains_key("unknown"));
        assert!(table.fields.contains_key("extra"));
    }
}
