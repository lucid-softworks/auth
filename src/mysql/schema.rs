use crate::{AdditionalFieldType, AuthError, DatabaseIdType, ResolvedAdapterSchema};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use sqlx::mysql::MySqlRow;
use std::collections::HashMap;

#[derive(Clone)]
pub(super) struct MySqlSchema {
    models: IndexMap<String, PhysicalModel>,
    logical_models: HashMap<String, LogicalModel>,
}

#[derive(Clone)]
pub(super) struct PhysicalModel {
    pub(super) table: String,
    pub(super) quoted_table: String,
    pub(super) id_type: DatabaseIdType,
    pub(super) columns: IndexMap<String, PhysicalColumn>,
    pub(super) disable_migrations: bool,
}

#[derive(Clone)]
pub(super) struct PhysicalColumn {
    pub(super) field: crate::AdditionalField,
}

#[derive(Clone)]
struct LogicalModel {
    physical: String,
    id_type: DatabaseIdType,
    columns: IndexMap<String, LogicalColumn>,
}

#[derive(Clone)]
struct LogicalColumn {
    quoted: String,
    field_type: AdditionalFieldType,
    bigint: bool,
    unique: bool,
    reference_id_type: Option<DatabaseIdType>,
}

pub(super) struct MySqlModel<'a> {
    logical_name: &'a str,
    logical: &'a LogicalModel,
    physical: &'a PhysicalModel,
}

impl MySqlSchema {
    pub(super) fn new(schema: &ResolvedAdapterSchema) -> Result<Self, AuthError> {
        let mut models = IndexMap::<String, PhysicalModel>::new();
        let mut enumerated = IndexMap::<String, LogicalModel>::new();
        for (logical_model, table) in schema.catalog().tables() {
            let physical_model = schema.adapter_model_name(table);
            let mut logical_columns = IndexMap::new();
            let model = models
                .entry(physical_model.clone())
                .or_insert_with(|| PhysicalModel {
                    table: physical_model.clone(),
                    quoted_table: quote(&physical_model),
                    id_type: table.id_type,
                    columns: IndexMap::new(),
                    disable_migrations: false,
                });
            model.disable_migrations |= table.disable_migrations;
            for (logical_field, field) in &table.fields {
                let physical_field = schema.adapter_field_name(logical_field, field).to_owned();
                model.columns.insert(
                    physical_field.clone(),
                    PhysicalColumn {
                        field: field.clone(),
                    },
                );
                logical_columns.insert(
                    logical_field.clone(),
                    LogicalColumn {
                        quoted: quote(&physical_field),
                        field_type: field.field_type,
                        bigint: field.bigint,
                        unique: field.unique,
                        reference_id_type: field.references.as_ref().and_then(|reference| {
                            (reference.field == "id")
                                .then(|| {
                                    schema.catalog().table(&reference.model).map(|t| t.id_type)
                                })
                                .flatten()
                        }),
                    },
                );
            }
            enumerated.insert(
                logical_model.clone(),
                LogicalModel {
                    physical: physical_model,
                    id_type: table.id_type,
                    columns: logical_columns,
                },
            );
        }
        let mut logical_models = HashMap::new();
        for runtime_input in schema.catalog().tables().keys() {
            let canonical = schema_error(schema.default_model_name(runtime_input))?;
            logical_models.insert(
                runtime_input.clone(),
                enumerated
                    .get(canonical)
                    .expect("resolved MySQL model is enumerated")
                    .clone(),
            );
        }
        Ok(Self {
            models,
            logical_models,
        })
    }

    pub(super) fn models(&self) -> impl Iterator<Item = &PhysicalModel> {
        self.models.values()
    }

    pub(super) fn model(&self, logical: &str) -> Result<MySqlModel<'_>, AuthError> {
        let (logical_name, logical_model) =
            self.logical_models.get_key_value(logical).ok_or_else(|| {
                AuthError::InvalidConfiguration(format!(
                    "MySQL schema has no logical model '{logical}'"
                ))
            })?;
        let physical = self
            .models
            .get(&logical_model.physical)
            .expect("every logical MySQL model has a physical model");
        Ok(MySqlModel {
            logical_name,
            logical: logical_model,
            physical,
        })
    }

}

impl MySqlModel<'_> {
    pub(super) fn quoted_table(&self) -> &str {
        &self.physical.quoted_table
    }

    pub(super) fn id_type(&self) -> DatabaseIdType {
        self.logical.id_type
    }

    pub(super) fn quoted_column(&self, logical: &str) -> Result<&str, AuthError> {
        if logical == "id" {
            return Ok("`id`");
        }
        self.logical
            .columns
            .get(logical)
            .map(|column| column.quoted.as_str())
            .ok_or_else(|| self.unknown_field(logical))
    }

    pub(super) fn field_type(
        &self,
        logical: &str,
    ) -> Result<(AdditionalFieldType, bool, Option<DatabaseIdType>), AuthError> {
        let column = self
            .logical
            .columns
            .get(logical)
            .ok_or_else(|| self.unknown_field(logical))?;
        Ok((column.field_type, column.bigint, column.reference_id_type))
    }

    pub(super) fn projection<'a>(
        &self,
        fields: impl IntoIterator<Item = &'a str>,
    ) -> Result<String, AuthError> {
        fields
            .into_iter()
            .map(|field| {
                let definition = self.logical.columns.get(field);
                Ok(format!(
                    "{} as {}",
                    projection_column(self.quoted_column(field)?, definition),
                    quote(field)
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|fields| fields.join(", "))
    }

    pub(super) fn all_projection(&self) -> String {
        std::iter::once("`id` as `id`".to_owned())
            .chain(
                self.logical
                    .columns
                    .iter()
                    .map(|(logical, column)| {
                        format!(
                            "{} as {}",
                            projection_column(&column.quoted, Some(column)),
                            quote(logical)
                        )
                    }),
            )
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(super) fn encode(
        &self,
        logical: &str,
        value: Value,
    ) -> Result<super::value::MySqlValue, AuthError> {
        if logical == "id" {
            return super::value::encode_id(self.logical.id_type, value);
        }
        let (field_type, bigint, reference_id_type) = self.field_type(logical)?;
        super::value::encode(logical, field_type, bigint, reference_id_type, value)
    }

    pub(super) fn encode_fields(
        &self,
        values: Map<String, Value>,
    ) -> Result<Vec<MySqlWrite>, AuthError> {
        let mut writes = Vec::with_capacity(values.len());
        for (logical, value) in values {
            writes.push(MySqlWrite {
                quoted_column: self.quoted_column(&logical)?.to_owned(),
                value: self.encode(&logical, value)?,
            });
        }
        Ok(writes)
    }

    pub(super) fn first_unique_value(&self, values: &Map<String, Value>) -> Option<(&str, Value)> {
        self.logical.columns.iter().find_map(|(logical, column)| {
            let value = values.get(logical)?;
            (column.unique && !value.is_null()).then(|| (logical.as_str(), value.clone()))
        })
    }

    pub(super) fn decode_all(&self, row: &MySqlRow) -> Result<Map<String, Value>, AuthError> {
        let mut values = Map::new();
        values.insert(
            "id".into(),
            super::value::decode_id(row, "id", self.logical.id_type)?,
        );
        for (logical, column) in &self.logical.columns {
            values.insert(
                logical.clone(),
                super::value::decode(
                    row,
                    logical,
                    column.field_type,
                    column.bigint,
                    column.reference_id_type,
                )?,
            );
        }
        Ok(values)
    }

    fn unknown_field(&self, logical: &str) -> AuthError {
        AuthError::InvalidConfiguration(format!(
            "MySQL schema model '{}' has no logical field '{logical}'",
            self.logical_name
        ))
    }
}

fn projection_column(column: &str, field: Option<&LogicalColumn>) -> String {
    if field.is_some_and(|field| {
        matches!(
            field.field_type,
            AdditionalFieldType::Json
                | AdditionalFieldType::StringArray
                | AdditionalFieldType::NumberArray
        )
    }) {
        format!("cast({column} as char)")
    } else {
        column.to_owned()
    }
}

pub(super) struct MySqlWrite {
    pub(super) quoted_column: String,
    pub(super) value: super::value::MySqlValue,
}

pub(super) fn quote(identifier: &str) -> String {
    format!("`{}`", identifier.replace('`', "``"))
}

fn schema_error<T>(result: Result<T, crate::SchemaResolutionError>) -> Result<T, AuthError> {
    result.map_err(|error| AuthError::InvalidConfiguration(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterSchemaOptions, AuthConfig, AuthSchemaCatalog};
    use std::sync::Arc;

    #[test]
    fn quotes_hostile_identifiers_and_resolves_remaps() {
        let mut config = AuthConfig::new([61; 32]).unwrap();
        config.user.model_name = Some("people `local`".into());
        config.user.fields.email = Some("mail `box`".into());
        let resolved = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()),
            AdapterSchemaOptions::default(),
        )
        .unwrap();
        let schema = MySqlSchema::new(&resolved).unwrap();
        let user = schema.model("user").unwrap();
        assert_eq!(user.quoted_table(), "`people ``local```");
        assert_eq!(user.quoted_column("email").unwrap(), "`mail ``box```");
        assert!(user.quoted_column("unknown").is_err());
    }
}
