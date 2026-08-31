use crate::{
    AdditionalFieldType, AuthError, DatabaseIdGenerationKind, ResolvedAdapterSchema,
    ResolvedDatabaseIndex,
};
use indexmap::IndexMap;
use mongodb::bson::{Bson, Document};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MongoIdEncoding {
    ObjectId,
    Uuid,
    Custom,
}

#[derive(Clone)]
pub(super) struct MongoSchema {
    models: IndexMap<String, PhysicalModel>,
    logical_models: HashMap<String, LogicalModel>,
    id_encoding: MongoIdEncoding,
}

#[derive(Clone)]
pub(super) struct PhysicalModel {
    pub(super) collection: String,
    pub(super) indexes: Vec<ResolvedDatabaseIndex>,
    pub(super) disable_migrations: bool,
}

#[derive(Clone)]
struct LogicalModel {
    physical: String,
    columns: IndexMap<String, LogicalColumn>,
}

#[derive(Clone)]
struct LogicalColumn {
    physical: String,
    field_type: AdditionalFieldType,
    bigint: bool,
    unique: bool,
    reference_to_id: bool,
}

pub(super) struct MongoModel<'a> {
    logical_name: &'a str,
    logical: &'a LogicalModel,
    physical: &'a PhysicalModel,
    id_encoding: MongoIdEncoding,
}

impl MongoSchema {
    pub(super) fn new(schema: &ResolvedAdapterSchema) -> Result<Self, AuthError> {
        let id_encoding = match schema.catalog().id_generation() {
            DatabaseIdGenerationKind::Uuid => MongoIdEncoding::Uuid,
            DatabaseIdGenerationKind::Callback => MongoIdEncoding::Custom,
            DatabaseIdGenerationKind::Default
            | DatabaseIdGenerationKind::Database
            | DatabaseIdGenerationKind::Serial => MongoIdEncoding::ObjectId,
        };
        let mut models = IndexMap::<String, PhysicalModel>::new();
        let mut enumerated = IndexMap::<String, LogicalModel>::new();
        for (logical_model, table) in schema.catalog().tables() {
            let physical_model = schema.adapter_model_name(table);
            let mut logical_columns = IndexMap::new();
            let model = models.entry(physical_model.clone()).or_insert_with(|| {
                let mut indexes = Vec::new();
                indexes.extend(
                    schema
                        .indexes_by_table()
                        .get(&physical_model)
                        .cloned()
                        .unwrap_or_default(),
                );
                deduplicate_indexes(&mut indexes);
                PhysicalModel {
                    collection: physical_model.clone(),
                    indexes,
                    disable_migrations: false,
                }
            });
            model.disable_migrations |= table.disable_migrations;
            for (logical_field, field) in &table.fields {
                let physical_field = schema.adapter_field_name(logical_field, field).to_owned();
                logical_columns.insert(
                    logical_field.clone(),
                    LogicalColumn {
                        physical: physical_field,
                        field_type: field.field_type,
                        bigint: field.bigint,
                        unique: field.unique,
                        reference_to_id: field
                            .references
                            .as_ref()
                            .is_some_and(|reference| reference.field == "id"),
                    },
                );
            }
            enumerated.insert(
                logical_model.clone(),
                LogicalModel {
                    physical: physical_model,
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
                    .expect("resolved MongoDB model is enumerated")
                    .clone(),
            );
        }
        Ok(Self {
            models,
            logical_models,
            id_encoding,
        })
    }

    pub(super) fn model(&self, logical: &str) -> Result<MongoModel<'_>, AuthError> {
        let (logical_name, logical_model) = self.logical_models.get_key_value(logical).ok_or_else(|| {
            AuthError::InvalidConfiguration(format!(
                "MongoDB schema has no logical model '{logical}'"
            ))
        })?;
        let physical = self
            .models
            .get(&logical_model.physical)
            .expect("every logical MongoDB model has a physical model");
        Ok(MongoModel {
            logical_name,
            logical: logical_model,
            physical,
            id_encoding: self.id_encoding,
        })
    }

    pub(super) fn has_model(&self, logical: &str) -> bool {
        self.logical_models.contains_key(logical)
    }
}

impl MongoModel<'_> {
    pub(super) fn collection(&self) -> &str {
        &self.physical.collection
    }

    pub(super) fn indexes(&self) -> &[ResolvedDatabaseIndex] {
        if self.physical.disable_migrations {
            &[]
        } else {
            &self.physical.indexes
        }
    }

    pub(super) fn has_field(&self, logical: &str) -> bool {
        logical == "id" || self.logical.columns.contains_key(logical)
    }

    pub(super) fn physical_field(&self, logical: &str) -> Result<&str, AuthError> {
        if matches!(logical, "id" | "_id") {
            return Ok("_id");
        }
        self.logical
            .columns
            .get(logical)
            .map(|column| column.physical.as_str())
            .ok_or_else(|| self.unknown_field(logical))
    }

    pub(super) fn quoted_column(&self, logical: &str) -> Result<&str, AuthError> {
        self.physical_field(logical)
    }

    pub(super) fn is_id(&self, logical: &str) -> Result<bool, AuthError> {
        if matches!(logical, "id" | "_id") {
            return Ok(true);
        }
        self.logical
            .columns
            .get(logical)
            .map(|column| column.reference_to_id)
            .ok_or_else(|| self.unknown_field(logical))
    }

    pub(super) fn unique(&self, logical: &str) -> Result<bool, AuthError> {
        if matches!(logical, "id" | "_id") {
            return Ok(true);
        }
        self.logical
            .columns
            .get(logical)
            .map(|column| column.unique)
            .ok_or_else(|| self.unknown_field(logical))
    }

    pub(super) fn encode(&self, logical: &str, value: Value) -> Result<Bson, AuthError> {
        if self.is_id(logical)? {
            return super::value::encode_id(self.id_encoding, value).map_err(Into::into);
        }
        let column = self
            .logical
            .columns
            .get(logical)
            .ok_or_else(|| self.unknown_field(logical))?;
        super::value::encode(logical, column.field_type, column.bigint, value)
    }

    pub(super) fn encode_fields(&self, values: Map<String, Value>) -> Result<Document, AuthError> {
        let mut document = Document::new();
        for (logical, value) in values {
            document.insert(self.physical_field(&logical)?, self.encode(&logical, value)?);
        }
        Ok(document)
    }

    pub(super) fn decode(&self, document: Document) -> Result<Map<String, Value>, AuthError> {
        let mut values = Map::new();
        for (logical, column) in &self.logical.columns {
            let value = document.get(&column.physical).cloned().unwrap_or(Bson::Null);
            values.insert(
                logical.clone(),
                if column.reference_to_id {
                    super::value::decode_id(value)?
                } else {
                    super::value::decode(value)?
                },
            );
        }
        if let Some(value) = document.get("_id") {
            values.insert("id".into(), super::value::decode_id(value.clone())?);
        }
        Ok(values)
    }

    pub(super) fn decode_selection(
        &self,
        document: Document,
        select: &[String],
    ) -> Result<Map<String, Value>, AuthError> {
        let all = self.decode(document)?;
        Ok(select
            .iter()
            .filter_map(|field| all.get(field).cloned().map(|value| (field.clone(), value)))
            .collect())
    }

    fn unknown_field(&self, logical: &str) -> AuthError {
        AuthError::InvalidConfiguration(format!(
            "MongoDB schema model '{}' has no logical field '{logical}'",
            self.logical_name
        ))
    }
}

fn deduplicate_indexes(indexes: &mut Vec<ResolvedDatabaseIndex>) {
    let mut definitions = HashSet::new();
    indexes.retain(|index| {
        definitions.insert((index.name.clone(), index.columns.clone(), index.unique))
    });
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
    fn resolves_remapped_collections_fields_and_mongo_id() {
        let mut config = AuthConfig::new([63; 32]).unwrap();
        config.user.model_name = Some("people".into());
        config.user.fields.email = Some("mailbox".into());
        let resolved = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()),
            AdapterSchemaOptions::default(),
        )
        .unwrap();
        let schema = MongoSchema::new(&resolved).unwrap();
        let user = schema.model("user").unwrap();
        assert_eq!(user.collection(), "people");
        assert_eq!(user.physical_field("id").unwrap(), "_id");
        assert_eq!(user.physical_field("email").unwrap(), "mailbox");
        assert!(user.physical_field("unknown").is_err());
    }
}
