use crate::{
    AdditionalField, AdditionalFieldType, AuthError, DatabaseIdType, ResolvedAdapterSchema,
};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::collections::HashMap;

#[derive(Clone)]
pub(super) struct D1Schema {
    models: IndexMap<String, PhysicalModel>,
    logical_models: HashMap<String, LogicalModel>,
}

#[derive(Clone)]
pub(super) struct PhysicalModel {
    pub table: String,
    pub quoted_table: String,
    pub id_type: DatabaseIdType,
    pub columns: IndexMap<String, PhysicalColumn>,
    pub disable_migrations: bool,
}

#[derive(Clone)]
pub(super) struct PhysicalColumn {
    pub field: AdditionalField,
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
    reference_id_type: Option<DatabaseIdType>,
}

pub(super) struct D1Model<'a> {
    logical_name: &'a str,
    logical: &'a LogicalModel,
    physical: &'a PhysicalModel,
}

pub(super) struct D1Write {
    pub quoted_column: String,
    pub value: super::transport::D1Value,
}

impl D1Schema {
    pub fn new(schema: &ResolvedAdapterSchema) -> Result<Self, AuthError> {
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
            let canonical = schema
                .default_model_name(runtime_input)
                .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
            logical_models.insert(
                runtime_input.clone(),
                enumerated
                    .get(canonical)
                    .expect("resolved D1 model is enumerated")
                    .clone(),
            );
        }
        Ok(Self {
            models,
            logical_models,
        })
    }

    pub fn model(&self, logical: &str) -> Result<D1Model<'_>, AuthError> {
        let (logical_name, logical_model) =
            self.logical_models.get_key_value(logical).ok_or_else(|| {
                AuthError::InvalidConfiguration(format!(
                    "D1 schema has no logical model '{logical}'"
                ))
            })?;
        let physical = self
            .models
            .get(&logical_model.physical)
            .expect("every logical D1 model has a physical model");
        Ok(D1Model {
            logical_name,
            logical: logical_model,
            physical,
        })
    }

    pub fn models(&self) -> impl Iterator<Item = &PhysicalModel> {
        self.models.values()
    }
}

impl D1Model<'_> {
    pub fn quoted_table(&self) -> &str {
        &self.physical.quoted_table
    }
    pub fn id_type(&self) -> DatabaseIdType {
        self.logical.id_type
    }

    pub fn quoted_column(&self, logical: &str) -> Result<&str, AuthError> {
        if logical == "id" {
            return Ok("\"id\"");
        }
        self.logical
            .columns
            .get(logical)
            .map(|column| column.quoted.as_str())
            .ok_or_else(|| self.unknown_field(logical))
    }

    pub fn field_type(
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

    pub fn projection<'a>(
        &self,
        fields: impl IntoIterator<Item = &'a str>,
    ) -> Result<String, AuthError> {
        fields
            .into_iter()
            .map(|field| {
                Ok(format!(
                    "{} as {}",
                    self.quoted_column(field)?,
                    quote(field)
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|fields| fields.join(", "))
    }

    pub fn all_projection(&self) -> String {
        std::iter::once("\"id\" as \"id\"".to_owned())
            .chain(
                self.logical
                    .columns
                    .iter()
                    .map(|(logical, column)| format!("{} as {}", column.quoted, quote(logical))),
            )
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn encode(
        &self,
        logical: &str,
        value: Value,
    ) -> Result<super::transport::D1Value, AuthError> {
        if logical == "id" {
            return super::value::encode_id(self.logical.id_type, value);
        }
        let (kind, bigint, reference) = self.field_type(logical)?;
        super::value::encode(logical, kind, bigint, reference, value)
    }

    pub fn encode_fields(&self, values: Map<String, Value>) -> Result<Vec<D1Write>, AuthError> {
        values
            .into_iter()
            .map(|(logical, value)| {
                Ok(D1Write {
                    quoted_column: self.quoted_column(&logical)?.to_owned(),
                    value: self.encode(&logical, value)?,
                })
            })
            .collect()
    }

    pub fn decode_all(&self, row: &Map<String, Value>) -> Result<Map<String, Value>, AuthError> {
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

    pub fn decode_selection(
        &self,
        row: &Map<String, Value>,
        fields: &[String],
    ) -> Result<Map<String, Value>, AuthError> {
        fields
            .iter()
            .map(|field| {
                let value = if field == "id" {
                    super::value::decode_id(row, field, self.id_type())?
                } else {
                    let (kind, bigint, reference) = self.field_type(field)?;
                    super::value::decode(row, field, kind, bigint, reference)?
                };
                Ok((field.clone(), value))
            })
            .collect()
    }

    fn unknown_field(&self, logical: &str) -> AuthError {
        AuthError::InvalidConfiguration(format!(
            "D1 schema model '{}' has no logical field '{logical}'",
            self.logical_name
        ))
    }
}

pub(super) fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}
