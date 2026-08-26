use super::*;
use crate::{
    AdapterSchemaOptions, AdditionalFieldReference, AuthConfig, AuthSchemaCatalog, DatabaseIdType,
    PluginSchemaTable,
};
use std::sync::Arc;

fn resolved(tables: Vec<PluginSchemaTable>) -> ResolvedAdapterSchema {
    let config = AuthConfig::new([18; 32]).unwrap();
    ResolvedAdapterSchema::new(
        Arc::new(AuthSchemaCatalog::build(&config, tables).unwrap()),
        AdapterSchemaOptions::default(),
    )
    .unwrap()
}

#[test]
fn text_ids_and_mixed_id_references_agree_across_ddl_objects_and_runtime() {
    let schema = resolved(vec![
        PluginSchemaTable::new("textParent").id_type(DatabaseIdType::String),
        PluginSchemaTable::new("mixedChild")
            .id_type(DatabaseIdType::String)
            .field(
                "parentId",
                AdditionalField::new(AdditionalFieldType::String).references(
                    AdditionalFieldReference {
                        model: "textParent".into(),
                        field: "id".into(),
                        on_delete: None,
                    },
                ),
            )
            .field(
                "userId",
                AdditionalField::new(AdditionalFieldType::String).references(
                    AdditionalFieldReference {
                        model: "user".into(),
                        field: "id".into(),
                        on_delete: None,
                    },
                ),
            ),
    ]);
    let physical = PostgresPhysicalSchema::new(&schema).unwrap();
    let sql = physical.migration_sql(&schema).unwrap();
    assert!(sql.contains("CREATE TABLE \"textParent\" (\n  \"id\" TEXT PRIMARY KEY"));
    assert!(sql.contains("CREATE TABLE \"mixedChild\" (\n  \"id\" TEXT PRIMARY KEY"));
    assert!(sql.contains("\"parentId\" TEXT NOT NULL REFERENCES \"textParent\"(\"id\")"));
    assert!(sql.contains("\"userId\" UUID NOT NULL REFERENCES \"user\"(\"id\")"));

    let objects = physical.schema_objects(&schema);
    assert!(objects.iter().any(|object| matches!(
        object,
        super::super::schema::PostgresSchemaObject::Column { table, name, data_type }
            if table == "mixedChild" && name == "id" && data_type == "text"
    )));

    let child = physical.model("mixedChild").unwrap();
    assert!(matches!(
        child.encode("id", serde_json::json!("child-1")).unwrap(),
        PostgresValue::Text(Some(value)) if value == "child-1"
    ));
    assert!(matches!(
        child
            .encode("parentId", serde_json::json!("parent-1"))
            .unwrap(),
        PostgresValue::Text(Some(value)) if value == "parent-1"
    ));
    assert!(matches!(
        child
            .encode("userId", serde_json::json!(uuid::Uuid::nil().to_string()))
            .unwrap(),
        PostgresValue::Uuid(Some(value)) if value == uuid::Uuid::nil()
    ));
}
