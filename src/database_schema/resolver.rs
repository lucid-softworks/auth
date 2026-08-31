use super::{AuthSchemaCatalog, SchemaFingerprint, SchemaTable};
#[cfg(any(
    feature = "postgres",
    feature = "mysql",
    feature = "mongodb",
    feature = "sqlite",
    feature = "d1"
))]
use crate::AdditionalField;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdapterSchemaOptions {
    pub use_plural: bool,
}

#[derive(Debug, Clone)]
pub struct ResolvedAdapterSchema {
    catalog: Arc<AuthSchemaCatalog>,
    options: AdapterSchemaOptions,
    fingerprint: SchemaFingerprint,
    indexes_by_table: indexmap::IndexMap<String, Vec<super::ResolvedDatabaseIndex>>,
    field_indexes_by_table: indexmap::IndexMap<String, Vec<super::ResolvedDatabaseIndex>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaResolutionError {
    #[error("Model \"{0}\" not found in schema")]
    ModelNotFound(String),
    #[error("Field {field} not found in model {model}")]
    FieldNotFound { model: String, field: String },
}

impl ResolvedAdapterSchema {
    pub fn new(
        catalog: Arc<AuthSchemaCatalog>,
        options: AdapterSchemaOptions,
    ) -> Result<Self, super::SchemaIndexError> {
        let fingerprint = SchemaFingerprint::for_adapter(&catalog, options.use_plural);
        let indexes_by_table = super::indexes::resolve_for_adapter(&catalog, options.use_plural)?;
        let field_indexes_by_table =
            super::indexes::resolve_field_indexes_for_adapter(&catalog, options.use_plural)?;
        Ok(Self {
            catalog,
            options,
            fingerprint,
            indexes_by_table,
            field_indexes_by_table,
        })
    }

    pub fn catalog(&self) -> &AuthSchemaCatalog {
        &self.catalog
    }

    pub fn fingerprint(&self) -> &SchemaFingerprint {
        &self.fingerprint
    }

    pub fn indexes_by_table(
        &self,
    ) -> &indexmap::IndexMap<String, Vec<super::ResolvedDatabaseIndex>> {
        &self.indexes_by_table
    }

    pub fn field_indexes_by_table(
        &self,
    ) -> &indexmap::IndexMap<String, Vec<super::ResolvedDatabaseIndex>> {
        &self.field_indexes_by_table
    }

    pub fn default_model_name(&self, input: &str) -> Result<&str, SchemaResolutionError> {
        if self.options.use_plural
            && input.ends_with('s')
            && let Some(resolved) = self.resolve_model(&input[..input.len() - 1])
        {
            return Ok(resolved);
        }
        self.resolve_model(input)
            .ok_or_else(|| SchemaResolutionError::ModelNotFound(input.into()))
    }

    pub fn model_name(&self, input: &str) -> Result<String, SchemaResolutionError> {
        let canonical = self.default_model_name(input)?;
        let selected = &self.catalog.tables()[canonical].model_name;
        Ok(if self.options.use_plural {
            format!("{selected}s")
        } else {
            selected.clone()
        })
    }

    #[cfg(any(
        feature = "postgres",
        feature = "mysql",
        feature = "mongodb",
        feature = "sqlite",
        feature = "d1"
    ))]
    pub(crate) fn adapter_model_name(&self, table: &SchemaTable) -> String {
        if self.options.use_plural {
            format!("{}s", table.model_name)
        } else {
            table.model_name.clone()
        }
    }

    #[cfg(any(
        feature = "postgres",
        feature = "mysql",
        feature = "mongodb",
        feature = "sqlite",
        feature = "d1"
    ))]
    pub(crate) fn adapter_field_name<'a>(
        &self,
        logical: &'a str,
        field: &'a AdditionalField,
    ) -> &'a str {
        field
            .field_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(logical)
    }

    #[cfg(any(
        feature = "postgres",
        feature = "mysql",
        feature = "mongodb",
        feature = "sqlite",
        feature = "d1"
    ))]
    pub(crate) fn adapter_reference_names(
        &self,
        model: &str,
        field_name: &str,
    ) -> Result<(String, String), SchemaResolutionError> {
        let table = self
            .catalog
            .table(model)
            .ok_or_else(|| SchemaResolutionError::ModelNotFound(model.into()))?;
        let column = if matches!(field_name, "id" | "_id") {
            "id".into()
        } else {
            let field = table.fields.get(field_name).ok_or_else(|| {
                SchemaResolutionError::FieldNotFound {
                    model: model.into(),
                    field: field_name.into(),
                }
            })?;
            self.adapter_field_name(field_name, field).into()
        };
        Ok((self.adapter_model_name(table), column))
    }

    pub fn default_field_name<'a>(
        &'a self,
        model: &str,
        input: &'a str,
    ) -> Result<&'a str, SchemaResolutionError> {
        if matches!(input, "id" | "_id") {
            return Ok("id");
        }
        let canonical_model = self.default_model_name(model)?;
        let table = &self.catalog.tables()[canonical_model];
        if table.fields.contains_key(input) {
            return Ok(input);
        }
        table
            .fields
            .iter()
            .find(|(_, field)| field.field_name.as_deref() == Some(input))
            .map(|(logical, _)| logical.as_str())
            .ok_or_else(|| SchemaResolutionError::FieldNotFound {
                model: canonical_model.into(),
                field: input.into(),
            })
    }

    pub fn field_name(&self, model: &str, input: &str) -> Result<String, SchemaResolutionError> {
        let canonical_model = self.default_model_name(model)?;
        let canonical_field = self.default_field_name(canonical_model, input)?;
        if canonical_field == "id" {
            return Ok("id".into());
        }
        let field = &self.catalog.tables()[canonical_model].fields[canonical_field];
        Ok(field
            .field_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(canonical_field)
            .into())
    }

    pub fn table(&self, model: &str) -> Result<&SchemaTable, SchemaResolutionError> {
        let canonical = self.default_model_name(model)?;
        Ok(&self.catalog.tables()[canonical])
    }

    fn resolve_model(&self, candidate: &str) -> Option<&str> {
        if let Some((logical, _)) = self.catalog.tables().get_key_value(candidate) {
            return Some(logical);
        }
        self.catalog
            .tables()
            .iter()
            .find(|(_, table)| table.model_name == candidate)
            .map(|(logical, _)| logical.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdditionalField, AdditionalFieldType, AuthConfig, PluginSchemaTable};

    fn schema(use_plural: bool) -> ResolvedAdapterSchema {
        let mut config = AuthConfig::new([5; 32]).unwrap();
        config.user.model_name = Some("person".into());
        config.user.fields.email = Some("mail box".into());
        ResolvedAdapterSchema::new(
            Arc::new(
                AuthSchemaCatalog::build(
                    &config,
                    [PluginSchemaTable::new("status").field(
                        "value",
                        AdditionalField::new(AdditionalFieldType::String)
                            .field_name("stored value"),
                    )],
                )
                .unwrap(),
            ),
            AdapterSchemaOptions { use_plural },
        )
        .unwrap()
    }

    #[test]
    fn resolves_canonical_configured_and_literal_plural_names() {
        let singular = schema(false);
        assert_eq!(singular.default_model_name("person").unwrap(), "user");
        assert_eq!(singular.model_name("user").unwrap(), "person");
        let plural = schema(true);
        assert_eq!(plural.default_model_name("persons").unwrap(), "user");
        assert_eq!(plural.model_name("person").unwrap(), "persons");
        assert_eq!(plural.model_name("status").unwrap(), "statuss");
    }

    #[test]
    fn resolves_id_alias_and_physical_fields() {
        let schema = schema(false);
        assert_eq!(schema.default_field_name("person", "_id").unwrap(), "id");
        assert_eq!(
            schema.default_field_name("user", "mail box").unwrap(),
            "email"
        );
        assert_eq!(schema.field_name("person", "email").unwrap(), "mail box");
        assert_eq!(
            schema.field_name("status", "stored value").unwrap(),
            "stored value"
        );
    }

    #[test]
    fn plural_stripping_precedes_exact_and_empty_physical_names_reverse_resolve() {
        let mut config = AuthConfig::new([6; 32]).unwrap();
        config.user.additional_fields.insert(
            "empty".into(),
            AdditionalField::new(AdditionalFieldType::String).field_name(""),
        );
        let schema = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, [PluginSchemaTable::new("users")]).unwrap()),
            AdapterSchemaOptions { use_plural: true },
        )
        .unwrap();
        assert_eq!(schema.default_model_name("users").unwrap(), "user");
        assert_eq!(schema.default_field_name("user", "").unwrap(), "empty");
        assert_eq!(schema.field_name("user", "").unwrap(), "empty");
    }
}
