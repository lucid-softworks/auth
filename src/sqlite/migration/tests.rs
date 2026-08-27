use super::*;
use crate::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthSchemaCatalog, DatabaseSchemaIndex,
    PluginSchemaTable,
};
use sqlx::{Row, sqlite::SqlitePoolOptions};
use std::sync::Arc;

async fn store() -> crate::sqlite::SqliteStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    crate::sqlite::SqliteStore::new(pool, crate::sqlite::SqliteAdapterConfig::default())
}

fn catalog(table: PluginSchemaTable) -> Arc<AuthSchemaCatalog> {
    Arc::new(AuthSchemaCatalog::build(&AuthConfig::new([61; 32]).unwrap(), [table]).unwrap())
}

#[tokio::test]
async fn creates_the_catalog_then_produces_the_pinned_empty_output() {
    let store = store().await;
    let schema = catalog(
        PluginSchemaTable::new("widget")
            .field(
                "tags",
                AdditionalField::new(AdditionalFieldType::StringArray),
            )
            .field(
                "active",
                AdditionalField::new(AdditionalFieldType::Boolean)
                    .default_value(serde_json::json!(true)),
            )
            .index(DatabaseSchemaIndex::new(["active"])),
    );
    let first = store.migrate(schema.clone()).await.unwrap();
    assert!(first.compiled_sql().contains("create table \"widget\""));
    assert!(first.compiled_sql().contains("\"active\" integer not null"));
    let second = store
        .migration_plan(schema, SqliteMigrationMode::Compile)
        .await
        .unwrap();
    assert_eq!(second.compiled_sql(), ";");
    assert!(
        second
            .warnings()
            .iter()
            .any(|warning| warning.contains("Expected string[] but got TEXT"))
    );
}

#[tokio::test]
async fn compile_reports_but_execute_rejects_an_unsafe_required_column() {
    let store = store().await;
    sqlx::query("create table widget (id text not null primary key)")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into widget (id) values ('one')")
        .execute(store.pool())
        .await
        .unwrap();
    let schema = catalog(PluginSchemaTable::new("widget").field(
        "requiredValue",
        AdditionalField::new(AdditionalFieldType::String),
    ));
    let compiled = store
        .migration_plan(schema.clone(), SqliteMigrationMode::Compile)
        .await
        .unwrap();
    assert_eq!(compiled.unsafe_changes().len(), 1);
    assert!(
        compiled
            .compiled_sql()
            .contains("add column \"requiredValue\" text not null")
    );
    assert!(matches!(
        store
            .migration_plan(schema, SqliteMigrationMode::Execute)
            .await,
        Err(SqliteMigrationError::Unsafe(_))
    ));
}

#[tokio::test]
async fn does_not_mutate_caller_pragma_policy() {
    let store = store().await;
    let before: i64 = sqlx::query("pragma foreign_keys")
        .fetch_one(store.pool())
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    store
        .migrate(catalog(PluginSchemaTable::new("widget")))
        .await
        .unwrap();
    let after: i64 = sqlx::query("pragma foreign_keys")
        .fetch_one(store.pool())
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn reports_type_nullable_and_generated_array_drift() {
    let store = store().await;
    sqlx::query(
        "create table widget (id text not null primary key, value blob, tags text not null)",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let schema = catalog(
        PluginSchemaTable::new("widget")
            .field("value", AdditionalField::new(AdditionalFieldType::String))
            .field(
                "tags",
                AdditionalField::new(AdditionalFieldType::StringArray),
            ),
    );
    let plan = store
        .migration_plan(schema, SqliteMigrationMode::Compile)
        .await
        .unwrap();
    assert!(
        plan.warnings()
            .iter()
            .any(|warning| warning.contains("stays nullable"))
    );
    assert!(
        plan.warnings()
            .iter()
            .any(|warning| warning.contains("Expected string but got BLOB"))
    );
    assert!(
        plan.warnings()
            .iter()
            .any(|warning| warning.contains("Expected string[] but got TEXT"))
    );
}

#[tokio::test]
async fn repairs_table_indexes_but_preserves_the_missing_field_index_quirk() {
    let table_index_store = store().await;
    sqlx::query("create table widget (id text not null primary key, value text not null)")
        .execute(table_index_store.pool())
        .await
        .unwrap();
    let table_index_schema = catalog(
        PluginSchemaTable::new("widget")
            .field("value", AdditionalField::new(AdditionalFieldType::String))
            .index(DatabaseSchemaIndex::new(["value"]).named("widget_value_idx")),
    );
    let plan = table_index_store
        .migration_plan(table_index_schema.clone(), SqliteMigrationMode::Execute)
        .await
        .unwrap();
    assert!(
        plan.compiled_sql()
            .contains("create index \"widget_value_idx\" on \"widget\" (\"value\")")
    );
    plan.run(table_index_store.pool()).await.unwrap();
    assert_eq!(
        table_index_store
            .migration_plan(table_index_schema, SqliteMigrationMode::Execute)
            .await
            .unwrap()
            .compiled_sql(),
        ";"
    );

    let field_index_store = store().await;
    sqlx::query("create table widget (id text not null primary key, value text not null)")
        .execute(field_index_store.pool())
        .await
        .unwrap();
    let field_index_schema = catalog(PluginSchemaTable::new("widget").field(
        "value",
        AdditionalField::new(AdditionalFieldType::String).index(true),
    ));
    let field_plan = field_index_store
        .migration_plan(field_index_schema, SqliteMigrationMode::Compile)
        .await
        .unwrap();
    assert!(!field_plan.steps().any(|step| matches!(
        step,
        SqliteMigrationStep::CreateIndex { table, .. } if table == "widget"
    )));
}

#[tokio::test]
async fn rejects_mismatched_partial_expression_and_foreign_indexes() {
    let fixtures = [
        "create table widget (id text not null primary key, value text not null, other text); create index widget_value_idx on widget (other)",
        "create table widget (id text not null primary key, value text not null); create index widget_value_idx on widget (value) where value is not null",
        "create table widget (id text not null primary key, value text not null); create index widget_value_idx on widget (lower(value))",
        "create table widget (id text not null primary key, value text not null); create table other (id text not null primary key, value text); create index WIDGET_VALUE_IDX on other (value)",
    ];
    for fixture in fixtures {
        let store = store().await;
        for statement in fixture
            .split(';')
            .filter(|statement| !statement.trim().is_empty())
        {
            sqlx::query(statement).execute(store.pool()).await.unwrap();
        }
        let schema = catalog(
            PluginSchemaTable::new("widget")
                .field("value", AdditionalField::new(AdditionalFieldType::String))
                .index(DatabaseSchemaIndex::new(["value"]).named("widget_value_idx")),
        );
        assert!(matches!(
            store
                .migration_plan(schema, SqliteMigrationMode::Compile)
                .await,
            Err(SqliteMigrationError::Conflict(_))
        ));
    }
}

#[tokio::test]
async fn static_defaults_are_safe_but_optional_unique_and_date_factories_are_not() {
    let safe = store().await;
    sqlx::query("create table widget (id text not null primary key)")
        .execute(safe.pool())
        .await
        .unwrap();
    sqlx::query("insert into widget (id) values ('one')")
        .execute(safe.pool())
        .await
        .unwrap();
    let safe_schema = catalog(PluginSchemaTable::new("widget").field(
        "active",
        AdditionalField::new(AdditionalFieldType::Boolean).default_value(serde_json::json!(true)),
    ));
    let safe_plan = safe
        .migration_plan(safe_schema, SqliteMigrationMode::Execute)
        .await
        .unwrap();
    assert!(
        safe_plan
            .compiled_sql()
            .contains("\"active\" integer not null default 1")
    );

    let unsafe_store = store().await;
    sqlx::query("create table widget (id text not null primary key)")
        .execute(unsafe_store.pool())
        .await
        .unwrap();
    sqlx::query("insert into widget (id) values ('one')")
        .execute(unsafe_store.pool())
        .await
        .unwrap();
    let unsafe_schema = catalog(
        PluginSchemaTable::new("widget")
            .field(
                "optionalUnique",
                AdditionalField::new(AdditionalFieldType::String)
                    .optional()
                    .unique(true)
                    .default_value(serde_json::json!("same")),
            )
            .field(
                "generatedAt",
                AdditionalField::new(AdditionalFieldType::Date).default_with(Arc::new(|| {
                    Ok(serde_json::json!("2024-01-01T00:00:00.000Z"))
                })),
            ),
    );
    let compiled = unsafe_store
        .migration_plan(unsafe_schema, SqliteMigrationMode::Compile)
        .await
        .unwrap();
    assert_eq!(compiled.unsafe_changes().len(), 1);
    assert!(compiled.compiled_sql().contains("\"optionalUnique\" text"));
    assert!(!compiled.compiled_sql().contains("default 'same'"));
    assert!(!compiled.compiled_sql().contains("CURRENT_TIMESTAMP"));
}
