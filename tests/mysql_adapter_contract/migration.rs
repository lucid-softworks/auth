use crate::support::{catalog, pool};
use lucid_auth::{
    AdditionalField, AdditionalFieldType, DatabaseSchemaIndex, PluginSchemaTable,
    mysql::{
        MySqlAdapterConfig, MySqlMigrationError, MySqlMigrationMode, MySqlMigrationStep, MySqlStore,
    },
};
use std::sync::Arc;

async fn store() -> MySqlStore {
    MySqlStore::new(pool(4).await, MySqlAdapterConfig::default())
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
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
        [61; 32],
    );
    let first = store.migrate(schema.clone()).await.unwrap();
    assert!(first.compiled_sql().contains("create table `widget`"));
    assert!(first.compiled_sql().contains("`active` boolean not null"));
    let second = store
        .migration_plan(schema, MySqlMigrationMode::Compile)
        .await
        .unwrap();
    assert_eq!(second.compiled_sql(), ";");
    assert!(second.warnings().is_empty());
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn compile_reports_but_execute_rejects_an_unsafe_required_column() {
    let store = store().await;
    sqlx::query("create table widget (id varchar(36) not null primary key)")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into widget (id) values ('one')")
        .execute(store.pool())
        .await
        .unwrap();
    let schema = catalog(
        PluginSchemaTable::new("widget").field(
            "requiredValue",
            AdditionalField::new(AdditionalFieldType::String),
        ),
        [61; 32],
    );
    let compiled = store
        .migration_plan(schema.clone(), MySqlMigrationMode::Compile)
        .await
        .unwrap();
    assert_eq!(compiled.unsafe_changes().len(), 1);
    assert!(
        compiled
            .compiled_sql()
            .contains("add column `requiredValue` text not null")
    );
    assert!(matches!(
        store
            .migration_plan(schema, MySqlMigrationMode::Execute)
            .await,
        Err(MySqlMigrationError::Unsafe(_))
    ));
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn does_not_mutate_caller_timezone_policy() {
    let store = store().await;
    let before: String = sqlx::query_scalar("select @@session.time_zone")
        .fetch_one(store.pool())
        .await
        .unwrap();
    store
        .migrate(catalog(PluginSchemaTable::new("widget"), [61; 32]))
        .await
        .unwrap();
    let after: String = sqlx::query_scalar("select @@session.time_zone")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn reports_type_nullable_and_generated_array_drift() {
    let store = store().await;
    sqlx::query(
        "create table widget (id varchar(36) not null primary key, value blob, tags text not null)",
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
        [61; 32],
    );
    let plan = store
        .migration_plan(schema, MySqlMigrationMode::Compile)
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
            .any(|warning| warning.contains("Expected string but got blob"))
    );
    assert!(
        plan.warnings()
            .iter()
            .any(|warning| warning.contains("Expected string[] but got text"))
    );
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn repairs_table_indexes_but_preserves_the_missing_field_index_quirk() {
    let table_index_store = store().await;
    sqlx::query(
        "create table widget (id varchar(36) not null primary key, value varchar(255) not null)",
    )
    .execute(table_index_store.pool())
    .await
    .unwrap();
    let table_index_schema = catalog(
        PluginSchemaTable::new("widget")
            .field("value", AdditionalField::new(AdditionalFieldType::String))
            .index(DatabaseSchemaIndex::new(["value"]).named("widget_value_idx")),
        [61; 32],
    );
    let plan = table_index_store
        .migration_plan(table_index_schema.clone(), MySqlMigrationMode::Execute)
        .await
        .unwrap();
    assert!(
        plan.compiled_sql()
            .contains("create index `widget_value_idx` on `widget` (`value`)")
    );
    plan.run(table_index_store.pool()).await.unwrap();
    assert_eq!(
        table_index_store
            .migration_plan(table_index_schema, MySqlMigrationMode::Execute)
            .await
            .unwrap()
            .compiled_sql(),
        ";"
    );

    let field_index_store = store().await;
    sqlx::query(
        "create table widget (id varchar(36) not null primary key, value varchar(255) not null)",
    )
    .execute(field_index_store.pool())
    .await
    .unwrap();
    let field_index_schema = catalog(
        PluginSchemaTable::new("widget").field(
            "value",
            AdditionalField::new(AdditionalFieldType::String).index(true),
        ),
        [61; 32],
    );
    let field_plan = field_index_store
        .migration_plan(field_index_schema, MySqlMigrationMode::Compile)
        .await
        .unwrap();
    assert!(!field_plan.steps().any(|step| matches!(
        step,
        MySqlMigrationStep::CreateIndex { table, .. } if table == "widget"
    )));
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn rejects_mismatched_and_prefix_indexes_but_allows_table_scoped_names() {
    let fixtures = [
        "create table widget (id varchar(36) not null primary key, value varchar(255) not null, other varchar(255)); create index widget_value_idx on widget (other)",
        "create table widget (id varchar(36) not null primary key, value varchar(255) not null); create index widget_value_idx on widget (value(20))",
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
            [61; 32],
        );
        assert!(
            matches!(
                store
                    .migration_plan(schema, MySqlMigrationMode::Compile)
                    .await,
                Err(MySqlMigrationError::Conflict(_))
            ),
            "fixture should conflict: {fixture}"
        );
    }

    let store = store().await;
    sqlx::query(
        "create table widget (id varchar(36) not null primary key, value varchar(255) not null)",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("create table other (id varchar(36) not null primary key, value varchar(255))")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("create index WIDGET_VALUE_IDX on other (value)")
        .execute(store.pool())
        .await
        .unwrap();
    let schema = catalog(
        PluginSchemaTable::new("widget")
            .field("value", AdditionalField::new(AdditionalFieldType::String))
            .index(DatabaseSchemaIndex::new(["value"]).named("widget_value_idx")),
        [61; 32],
    );
    assert!(
        store
            .migration_plan(schema, MySqlMigrationMode::Compile)
            .await
            .is_ok()
    );
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn static_defaults_are_safe_but_optional_unique_and_date_factories_are_not() {
    let safe = store().await;
    sqlx::query("create table widget (id varchar(36) not null primary key)")
        .execute(safe.pool())
        .await
        .unwrap();
    sqlx::query("insert into widget (id) values ('one')")
        .execute(safe.pool())
        .await
        .unwrap();
    let safe_schema = catalog(
        PluginSchemaTable::new("widget").field(
            "active",
            AdditionalField::new(AdditionalFieldType::Boolean)
                .default_value(serde_json::json!(true)),
        ),
        [61; 32],
    );
    let safe_plan = safe
        .migration_plan(safe_schema, MySqlMigrationMode::Execute)
        .await
        .unwrap();
    assert!(
        safe_plan
            .compiled_sql()
            .contains("`active` boolean not null default 1")
    );

    let unsafe_store = store().await;
    sqlx::query("create table widget (id varchar(36) not null primary key)")
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
        [61; 32],
    );
    let compiled = unsafe_store
        .migration_plan(unsafe_schema, MySqlMigrationMode::Compile)
        .await
        .unwrap();
    assert!(
        compiled
            .compiled_sql()
            .contains("`optionalUnique` varchar(191)")
    );
    assert!(!compiled.compiled_sql().contains("default 'same'"));
    assert!(compiled.compiled_sql().contains("CURRENT_TIMESTAMP(3)"));
}
