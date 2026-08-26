use crate::{
    AdditionalField, AdditionalFieldType, AuthError, DatabaseIdType, ResolvedAdapterSchema,
};
use indexmap::IndexMap;

#[cfg(test)]
mod collision_tests;
mod ddl;
mod evolve;
mod objects;
mod runtime;
#[cfg(test)]
mod typed_id_tests;

#[cfg(test)]
pub(crate) use runtime::PostgresValue;
pub(crate) use runtime::{PostgresModel, PostgresWrite};

#[derive(Clone)]
pub(super) struct PostgresPhysicalSchema {
    models: IndexMap<String, PhysicalModel>,
    logical_models: std::collections::HashMap<String, LogicalModel>,
}

#[derive(Clone)]
pub(super) struct PhysicalModel {
    pub(super) table: String,
    pub(super) quoted_table: String,
    id_type: DatabaseIdType,
    columns: IndexMap<String, PhysicalColumn>,
    disable_migrations: bool,
}

#[derive(Clone)]
struct PhysicalColumn {
    field: AdditionalField,
    aliases: Vec<(String, String)>,
}

#[derive(Clone)]
struct LogicalModel {
    physical: String,
    id_type: DatabaseIdType,
    columns: IndexMap<String, LogicalColumn>,
}

#[derive(Clone)]
struct LogicalColumn {
    physical: String,
    quoted: String,
    field_type: AdditionalFieldType,
    bigint: bool,
    reference_id_type: Option<DatabaseIdType>,
}

impl PostgresPhysicalSchema {
    pub(super) fn new(schema: &ResolvedAdapterSchema) -> Result<Self, AuthError> {
        physical_models(schema)
    }

    pub(crate) fn model(&self, logical: &str) -> Result<PostgresModel<'_>, AuthError> {
        self.model_if_present(logical).ok_or_else(|| {
            AuthError::InvalidConfiguration(format!(
                "PostgreSQL schema has no logical model '{logical}'"
            ))
        })
    }

    pub(crate) fn model_if_present(&self, logical: &str) -> Option<PostgresModel<'_>> {
        let (logical_name, logical_model) = self.logical_models.get_key_value(logical)?;
        let physical = self
            .models
            .get(&logical_model.physical)
            .expect("every logical PostgreSQL model has a physical model");
        Some(PostgresModel::new(logical_name, logical_model, physical))
    }

    #[cfg(test)]
    pub(super) fn migration_sql(
        &self,
        schema: &ResolvedAdapterSchema,
    ) -> Result<String, AuthError> {
        ddl::render_migration(schema, &self.models)
    }

    pub(super) async fn migrate(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        schema: &ResolvedAdapterSchema,
    ) -> Result<(), AuthError> {
        evolve::migrate(transaction, schema, &self.models).await
    }

    pub(super) fn schema_objects(
        &self,
        schema: &ResolvedAdapterSchema,
    ) -> Vec<super::schema::PostgresSchemaObject> {
        objects::schema_objects(self, schema)
    }
}

fn physical_models(schema: &ResolvedAdapterSchema) -> Result<PostgresPhysicalSchema, AuthError> {
    let mut models = IndexMap::<String, PhysicalModel>::new();
    let mut enumerated_logical_models = IndexMap::<String, LogicalModel>::new();
    for (logical_model, table) in schema.catalog().tables() {
        let physical_model = schema.adapter_model_name(table);
        let mut logical_columns = IndexMap::new();
        let model = models
            .entry(physical_model.clone())
            .or_insert_with(|| PhysicalModel {
                quoted_table: quote(&physical_model),
                table: physical_model.clone(),
                id_type: table.id_type,
                columns: IndexMap::new(),
                disable_migrations: false,
            });
        model.disable_migrations |= table.disable_migrations;
        for (logical_field, field) in &table.fields {
            let physical_field = schema.adapter_field_name(logical_field, field).to_owned();
            let column = model
                .columns
                .entry(physical_field.clone())
                .or_insert_with(|| PhysicalColumn {
                    field: field.clone(),
                    aliases: Vec::new(),
                });
            column.field = field.clone();
            column
                .aliases
                .push((logical_model.clone(), logical_field.clone()));
            logical_columns.insert(
                logical_field.clone(),
                LogicalColumn {
                    quoted: quote(&physical_field),
                    physical: physical_field,
                    field_type: field.field_type,
                    bigint: field.bigint,
                    reference_id_type: field.references.as_ref().and_then(|reference| {
                        (reference.field == "id")
                            .then(|| schema.catalog().table(&reference.model).map(|t| t.id_type))
                            .flatten()
                    }),
                },
            );
        }
        enumerated_logical_models.insert(
            logical_model.clone(),
            LogicalModel {
                physical: physical_model,
                id_type: table.id_type,
                columns: logical_columns,
            },
        );
    }
    let mut logical_models = std::collections::HashMap::new();
    for runtime_input in schema.catalog().tables().keys() {
        let resolved_logical = schema_error(schema.default_model_name(runtime_input))?;
        let logical = enumerated_logical_models
            .get(resolved_logical)
            .expect("runtime schema resolution must select an enumerated logical model")
            .clone();
        logical_models.insert(runtime_input.clone(), logical);
    }
    Ok(PostgresPhysicalSchema {
        models,
        logical_models,
    })
}

fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn schema_error<T>(result: Result<T, crate::SchemaResolutionError>) -> Result<T, AuthError> {
    result.map_err(|error| AuthError::InvalidConfiguration(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AdditionalFieldOnDelete, AdditionalFieldReference, AuthConfig,
        AuthSchemaCatalog, PluginSchemaTable,
    };
    use std::sync::Arc;

    fn resolved(tables: Vec<PluginSchemaTable>) -> ResolvedAdapterSchema {
        let config = AuthConfig::new([13; 32]).unwrap();
        ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, tables).unwrap()),
            AdapterSchemaOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn disabled_aliases_remain_runtime_visible_and_disable_merged_ddl() {
        let schema = resolved(vec![
            PluginSchemaTable::new("externalOne")
                .model_name("shared")
                .field("one", AdditionalField::new(AdditionalFieldType::String))
                .disable_migration(true),
            PluginSchemaTable::new("externalTwo")
                .model_name("shared")
                .field("two", AdditionalField::new(AdditionalFieldType::String)),
        ]);
        let physical = PostgresPhysicalSchema::new(&schema).unwrap();
        assert_eq!(physical.model("externalOne").unwrap().table(), "shared");
        assert_eq!(physical.model("externalTwo").unwrap().table(), "shared");
        assert!(
            !physical
                .migration_sql(&schema)
                .unwrap()
                .contains("\"shared\"")
        );
    }

    #[test]
    fn omitted_delete_policy_is_metadata_distinct_but_ddl_defaults_to_cascade() {
        let schema = resolved(vec![
            PluginSchemaTable::new("omitted").field(
                "userId",
                AdditionalField::new(AdditionalFieldType::String).references(
                    AdditionalFieldReference {
                        model: "user".into(),
                        field: "id".into(),
                        on_delete: None,
                    },
                ),
            ),
            PluginSchemaTable::new("explicit").field(
                "userId",
                AdditionalField::new(AdditionalFieldType::String).references(
                    AdditionalFieldReference {
                        model: "user".into(),
                        field: "id".into(),
                        on_delete: Some(AdditionalFieldOnDelete::SetNull),
                    },
                ),
            ),
        ]);
        assert_eq!(
            schema.catalog().tables()["omitted"].fields["userId"]
                .references
                .as_ref()
                .unwrap()
                .on_delete,
            None
        );
        let sql = PostgresPhysicalSchema::new(&schema)
            .unwrap()
            .migration_sql(&schema)
            .unwrap();
        assert!(sql.contains("CREATE TABLE \"omitted\""));
        assert!(sql.contains("\"userId\" UUID NOT NULL REFERENCES"));
        assert!(sql.contains("REFERENCES \"user\"(\"id\") ON DELETE CASCADE"));
        assert!(sql.contains("REFERENCES \"user\"(\"id\") ON DELETE SET NULL"));
    }

    #[test]
    fn retained_field_indexes_survive_later_physical_column_collapse() {
        let schema = resolved(vec![
            PluginSchemaTable::new("first").model_name("shared").field(
                "lookup",
                AdditionalField::new(AdditionalFieldType::String)
                    .field_name("lookup_column")
                    .index(true),
            ),
            PluginSchemaTable::new("second").model_name("shared").field(
                "replacement",
                AdditionalField::new(AdditionalFieldType::String).field_name("lookup_column"),
            ),
        ]);
        let sql = PostgresPhysicalSchema::new(&schema)
            .unwrap()
            .migration_sql(&schema)
            .unwrap();
        assert!(sql.contains(
            "CREATE INDEX \"shared_lookup_column_idx\" ON \"shared\" (\"lookup_column\")"
        ));
    }

    #[test]
    fn create_and_add_column_defaults_follow_better_auth_migration_rules() {
        let schema = resolved(vec![]);
        let required = AdditionalField::new(AdditionalFieldType::String)
            .default_value(serde_json::json!("it's ready"))
            .unique(true);
        let created = ddl::create_column_definition(&schema, "state", &required).unwrap();
        assert_eq!(created, "\"state\" TEXT NOT NULL UNIQUE");
        let added = ddl::add_column_definition(&schema, "state", &required).unwrap();
        assert_eq!(added, "\"state\" TEXT NOT NULL DEFAULT 'it''s ready'");

        let optional_unique = AdditionalField::new(AdditionalFieldType::Boolean)
            .optional()
            .unique(true)
            .default_value(serde_json::json!(false));
        let added = ddl::add_column_definition(&schema, "available", &optional_unique).unwrap();
        assert_eq!(added, "\"available\" BOOLEAN");

        let optional_unique_date = AdditionalField::new(AdditionalFieldType::Date)
            .optional()
            .unique(true)
            .default_with(Arc::new(|| Ok(serde_json::json!("unused"))));
        let added =
            ddl::add_column_definition(&schema, "observedAt", &optional_unique_date).unwrap();
        assert_eq!(
            added,
            "\"observedAt\" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"
        );

        let literal =
            AdditionalField::new(AdditionalFieldType::StringLiteral(&["ready", "waiting"]))
                .default_value(serde_json::json!("ready"));
        assert_eq!(ddl::add_column_default(&literal), None);
    }

    #[test]
    fn runtime_model_quotes_hostile_identifiers_and_projects_canonical_aliases() {
        let mut config = AuthConfig::new([14; 32]).unwrap();
        config.user.model_name = Some("odd \" people".into());
        config.user.fields.email = Some("select \" mail".into());
        let schema = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()),
            AdapterSchemaOptions::default(),
        )
        .unwrap();
        let physical = PostgresPhysicalSchema::new(&schema).unwrap();
        let user = physical.model("user").unwrap();
        assert_eq!(user.quoted_table(), "\"odd \"\" people\"");
        assert_eq!(user.column("email").unwrap(), "select \" mail");
        assert_eq!(user.quoted_column("email").unwrap(), "\"select \"\" mail\"");
        assert_eq!(
            user.projection(["id", "email"]).unwrap(),
            "\"id\" AS \"id\", \"select \"\" mail\" AS \"email\""
        );
        assert!(user.has_field("email"));
        assert!(!user.has_field("missing"));
    }

    #[test]
    fn runtime_codec_is_structural_and_does_not_execute_schema_callbacks() {
        let mut config = AuthConfig::new([15; 32]).unwrap();
        config.user.additional_fields.insert(
            "score".into(),
            AdditionalField::new(AdditionalFieldType::Number),
        );
        config.user.additional_fields.insert(
            "seenAt".into(),
            AdditionalField::new(AdditionalFieldType::Date).transform_input(Arc::new(|_| {
                panic!("the PostgreSQL structural codec must not execute schema callbacks")
            })),
        );
        let schema = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()),
            AdapterSchemaOptions::default(),
        )
        .unwrap();
        let physical = PostgresPhysicalSchema::new(&schema).unwrap();
        let user = physical.model("user").unwrap();
        assert!(matches!(
            user.encode("score", serde_json::json!(42)).unwrap(),
            PostgresValue::Integer(Some(42))
        ));
        assert!(matches!(
            user.encode("seenAt", serde_json::json!("2026-08-26T12:00:00Z"))
                .unwrap(),
            PostgresValue::Date(Some(_))
        ));
    }

    #[test]
    fn runtime_writes_collapse_physical_aliases_with_later_input_winning() {
        let mut config = AuthConfig::new([16; 32]).unwrap();
        config.user.additional_fields.insert(
            "first".into(),
            AdditionalField::new(AdditionalFieldType::String).field_name("shared"),
        );
        config.user.additional_fields.insert(
            "second".into(),
            AdditionalField::new(AdditionalFieldType::String).field_name("shared"),
        );
        let schema = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()),
            AdapterSchemaOptions::default(),
        )
        .unwrap();
        let physical = PostgresPhysicalSchema::new(&schema).unwrap();
        let user = physical.model("user").unwrap();
        let writes = user
            .encode_fields([
                ("second", serde_json::json!("new")),
                ("unknown", serde_json::json!("ignored")),
                ("first", serde_json::json!("old")),
            ])
            .unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].logical(), "second");
        assert_eq!(writes[0].column(), "shared");
        assert_eq!(writes[0].quoted_column(), "\"shared\"");
        assert!(matches!(
            writes[0].value(),
            PostgresValue::Text(Some(value)) if value == "new"
        ));
    }

    #[test]
    fn adapter_owned_postgres_schema_uses_naive_plural_table_names() {
        let config = AuthConfig::new([17; 32]).unwrap();
        let schema = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()),
            AdapterSchemaOptions { use_plural: true },
        )
        .unwrap();
        let sql = PostgresPhysicalSchema::new(&schema)
            .unwrap()
            .migration_sql(&schema)
            .unwrap();

        for table in ["users", "sessions", "accounts", "verifications"] {
            assert!(
                sql.contains(&format!("CREATE TABLE \"{table}\"")),
                "missing plural adapter-owned table {table} in:\n{sql}"
            );
        }
        assert!(!sql.contains("CREATE TABLE \"user\""));
    }
}
