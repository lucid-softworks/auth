#![cfg(feature = "d1")]

use async_trait::async_trait;
use lucid_auth::d1::{
    D1AdapterConfig, D1Database, D1Filter, D1MigrationMode, D1QueryResult, D1Statement, D1Store,
    D1TransportError, D1Value,
};
use lucid_auth::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthPlugin, AuthSchemaCatalog, AuthService,
    DatabaseSchemaIndex, MemoryStore, PluginDescriptor, PluginProvenance, PluginSchemaTable,
};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct RecordingD1 {
    statements: Mutex<Vec<D1Statement>>,
    batches: Mutex<Vec<Vec<D1Statement>>>,
}

#[derive(Default)]
struct AtomicD1 {
    state: Mutex<(bool, i64)>,
}

struct MigrationFixtureD1 {
    columns: Vec<Map<String, Value>>,
    index_list: Vec<Map<String, Value>>,
    index_columns: Vec<Map<String, Value>>,
    populated: bool,
}

#[async_trait]
impl D1Database for MigrationFixtureD1 {
    async fn all(&self, statement: D1Statement) -> Result<D1QueryResult, D1TransportError> {
        let results = if statement
            .sql
            .starts_with("select \"name\", \"type\", \"sql\" from \"sqlite_master\"")
        {
            vec![Map::from_iter([
                ("name".into(), json!("counter")),
                ("type".into(), json!("table")),
                (
                    "sql".into(),
                    json!("create table counter (id text primary key)"),
                ),
            ])]
        } else if statement.sql.contains("pragma_index_list") {
            self.index_list.clone()
        } else if statement.sql.contains("pragma_index_xinfo") {
            self.index_columns.clone()
        } else if statement.sql.starts_with("select 1 from \"counter\"") && self.populated {
            vec![Map::from_iter([("1".into(), json!(1))])]
        } else {
            vec![]
        };
        Ok(D1QueryResult {
            results,
            changes: None,
            last_row_id: None,
        })
    }

    async fn batch_all(
        &self,
        statements: Vec<D1Statement>,
    ) -> Result<Vec<D1QueryResult>, D1TransportError> {
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].sql, "SELECT * FROM pragma_table_info(?)");
        Ok(vec![D1QueryResult {
            results: self.columns.clone(),
            changes: None,
            last_row_id: None,
        }])
    }
}

#[async_trait]
impl D1Database for AtomicD1 {
    async fn all(&self, statement: D1Statement) -> Result<D1QueryResult, D1TransportError> {
        let mut state = self.state.lock().unwrap();
        if statement.sql.starts_with("delete from \"counter\"") {
            if state.0 {
                return Ok(D1QueryResult::default());
            }
            state.0 = true;
            return Ok(D1QueryResult {
                results: vec![counter_row("row-1", "Atomic", state.1)],
                changes: Some(1),
                last_row_id: None,
            });
        }
        if statement.sql.starts_with("update \"counter\"") {
            let delta = statement
                .parameters
                .iter()
                .find_map(|value| match value {
                    D1Value::Integer(value) => Some(*value),
                    _ => None,
                })
                .unwrap();
            state.1 += delta;
            return Ok(D1QueryResult {
                results: vec![counter_row("row-1", "Atomic", state.1)],
                changes: Some(1),
                last_row_id: None,
            });
        }
        Ok(D1QueryResult::default())
    }
    async fn batch_all(
        &self,
        statements: Vec<D1Statement>,
    ) -> Result<Vec<D1QueryResult>, D1TransportError> {
        Ok(statements
            .into_iter()
            .map(|_| D1QueryResult::default())
            .collect())
    }
}

#[async_trait]
impl D1Database for RecordingD1 {
    async fn all(&self, statement: D1Statement) -> Result<D1QueryResult, D1TransportError> {
        let result = response(&statement);
        self.statements.lock().unwrap().push(statement);
        result
    }

    async fn batch_all(
        &self,
        statements: Vec<D1Statement>,
    ) -> Result<Vec<D1QueryResult>, D1TransportError> {
        self.batches.lock().unwrap().push(statements.clone());
        Ok(statements
            .into_iter()
            .map(|_| D1QueryResult::default())
            .collect())
    }
}

fn response(statement: &D1Statement) -> Result<D1QueryResult, D1TransportError> {
    if statement
        .parameters
        .contains(&D1Value::Text("forced_failure".into()))
    {
        return Err(D1TransportError::new("redacted D1 failure"));
    }
    if statement
        .sql
        .starts_with("select \"name\", \"type\", \"sql\" from \"sqlite_master\"")
    {
        return Ok(D1QueryResult::default());
    }
    if statement.sql.starts_with("insert into \"counter\"") {
        return Ok(D1QueryResult {
            results: vec![counter_row("row-1", "' hostile ? --", 4)],
            changes: Some(1),
            last_row_id: None,
        });
    }
    if statement.sql.starts_with("delete from \"counter\"") {
        return Ok(D1QueryResult {
            results: vec![counter_row("row-1", "Alpha", 4)],
            changes: Some(1),
            last_row_id: None,
        });
    }
    if statement.sql.starts_with("update \"counter\"") {
        return Ok(D1QueryResult {
            results: vec![counter_row("row-1", "Updated", 7)],
            changes: Some(1),
            last_row_id: None,
        });
    }
    Ok(D1QueryResult::default())
}

fn counter_row(id: &str, label: &str, count: i64) -> Map<String, Value> {
    Map::from_iter([
        ("id".into(), json!(id)),
        ("label".into(), json!(label)),
        ("count".into(), json!(count)),
    ])
}

fn schema() -> Arc<AuthSchemaCatalog> {
    let mut config = AuthConfig::new([96; 32]).unwrap();
    config.add_plugin(CounterPlugin).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    Arc::new(service.database_schema().clone())
}

struct CounterPlugin;

#[async_trait]
impl AuthPlugin for CounterPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "d1-counter-test",
            display_name: "D1 counter test",
            version: "1.0.0",
            provenance: PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        vec![
            PluginSchemaTable::new("counter")
                .field("label", AdditionalField::new(AdditionalFieldType::String))
                .field("count", AdditionalField::new(AdditionalFieldType::Number))
                .index(DatabaseSchemaIndex::new(["label"]).named("counter_label_idx")),
        ]
    }
}

fn store(database: Arc<dyn D1Database>) -> D1Store {
    let store = D1Store::new(database, D1AdapterConfig::default());
    store.bind_schema(schema()).unwrap();
    store
}

#[tokio::test]
async fn binds_values_and_uses_single_statement_atomic_primitives() {
    let database = Arc::new(RecordingD1::default());
    let store = store(database.clone());
    let inserted = store
        .insert_record(
            "counter",
            Map::from_iter([
                ("id".into(), json!("row-1")),
                ("label".into(), json!("' hostile ? --")),
                ("count".into(), json!(4)),
            ]),
        )
        .await
        .unwrap();
    assert_eq!(inserted["label"], "' hostile ? --");

    let consumed = store
        .consume_record("counter", &[D1Filter::equal("id", json!("row-1"))])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(consumed["id"], "row-1");
    let incremented = store
        .increment_record(
            "counter",
            &[D1Filter::equal("id", json!("row-1"))],
            Map::from_iter([("count".into(), json!(3))]),
            Map::from_iter([("label".into(), json!("Updated"))]),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incremented["count"], 7);

    let statements = database.statements.lock().unwrap();
    assert_eq!(statements.len(), 3);
    assert!(!statements[0].sql.contains("hostile"));
    assert!(
        statements[0]
            .parameters
            .contains(&D1Value::Text("' hostile ? --".into()))
    );
    assert!(
        statements[1]
            .sql
            .contains("delete from \"counter\" where \"id\" in (select \"id\"")
    );
    assert!(statements[1].sql.contains("limit 1) returning"));
    assert!(statements[2].sql.contains("\"count\" = \"count\" + ?"));
    assert!(statements[2].sql.contains("limit 1) returning"));
}

#[tokio::test]
async fn reports_capabilities_and_transport_errors_explicitly() {
    let database = Arc::new(RecordingD1::default());
    let store = store(database);
    assert!(!store.supports_transactions());
    assert_eq!(
        store.begin_transaction().unwrap_err().to_string(),
        "authentication storage failed: D1 does not support interactive transactions. Use atomic adapter operations instead."
    );
    assert_eq!(
        store.stream_records().unwrap_err().to_string(),
        "authentication storage failed: D1 does not support streaming queries."
    );
    let error = store
        .find_record(
            "counter",
            &[D1Filter::equal("label", json!("forced_failure"))],
            &[],
        )
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("bound"));
}

#[tokio::test]
async fn empty_migration_uses_bound_statements_and_runs_sequentially() {
    let database = Arc::new(RecordingD1::default());
    let store = D1Store::new(database.clone(), D1AdapterConfig::default());
    let plan = store
        .migration_plan(schema(), D1MigrationMode::Compile)
        .await
        .unwrap();
    assert!(plan.compiled_sql().contains("create table \"counter\""));
    assert!(database.batches.lock().unwrap().is_empty());
    let before = database.statements.lock().unwrap().len();
    plan.run(database.as_ref()).await.unwrap();
    let statements = database.statements.lock().unwrap();
    assert!(statements.len() > before);
    assert!(
        statements[before..]
            .iter()
            .all(|statement| statement.parameters.is_empty())
    );
}

#[tokio::test]
async fn concurrent_calls_cannot_replay_consume_or_lose_increments() {
    let database = Arc::new(AtomicD1::default());
    let store = Arc::new(store(database.clone()));
    let mut consumes = Vec::new();
    for _ in 0..32 {
        let store = store.clone();
        consumes.push(tokio::spawn(async move {
            store
                .consume_record("counter", &[D1Filter::equal("id", json!("row-1"))])
                .await
                .unwrap()
                .is_some()
        }));
    }
    let mut consumed = 0;
    for task in consumes {
        consumed += usize::from(task.await.unwrap());
    }
    assert_eq!(consumed, 1);

    let mut increments = Vec::new();
    for _ in 0..100 {
        let store = store.clone();
        increments.push(tokio::spawn(async move {
            store
                .increment_record(
                    "counter",
                    &[D1Filter::equal("id", json!("row-1"))],
                    Map::from_iter([("count".into(), json!(1))]),
                    Map::new(),
                )
                .await
                .unwrap()
        }));
    }
    for task in increments {
        task.await.unwrap();
    }
    assert_eq!(database.state.lock().unwrap().1, 100);
}

#[test]
fn preserves_absent_d1_metadata_without_inventing_values() {
    assert_eq!(D1QueryResult::default().changes, None);
    assert_eq!(D1QueryResult::default().last_row_id, None);
}

fn pragma_column(
    name: &str,
    data_type: &str,
    required: bool,
    primary_key: bool,
) -> Map<String, Value> {
    Map::from_iter([
        ("name".into(), json!(name)),
        ("type".into(), json!(data_type)),
        ("notnull".into(), json!(i64::from(required))),
        ("pk".into(), json!(i64::from(primary_key))),
    ])
}

#[tokio::test]
async fn migration_reports_partial_unsafe_and_drifted_d1_catalogs() {
    let partial = Arc::new(MigrationFixtureD1 {
        columns: vec![pragma_column("id", "TEXT", true, true)],
        index_list: vec![],
        index_columns: vec![],
        populated: true,
    });
    let compiled = D1Store::new(partial, D1AdapterConfig::default())
        .migration_plan(schema(), D1MigrationMode::Compile)
        .await
        .unwrap();
    assert_eq!(compiled.unsafe_changes().len(), 2);
    assert!(
        compiled
            .unsafe_changes()
            .iter()
            .all(|change| change.contains("populated D1 table") && !change.contains("MySQL"))
    );
    assert!(compiled.compiled_sql().contains("add column \"label\""));

    let drifted = Arc::new(MigrationFixtureD1 {
        columns: vec![
            pragma_column("id", "TEXT", true, true),
            pragma_column("label", "INTEGER", false, false),
            pragma_column("count", "TEXT", true, false),
        ],
        index_list: vec![],
        index_columns: vec![],
        populated: false,
    });
    let drift = D1Store::new(drifted, D1AdapterConfig::default())
        .migration_plan(schema(), D1MigrationMode::Compile)
        .await
        .unwrap();
    assert!(
        drift
            .warnings()
            .iter()
            .any(|warning| warning.contains("stays nullable"))
    );
    assert!(
        drift
            .warnings()
            .iter()
            .filter(|warning| warning.contains("different type"))
            .count()
            >= 2
    );
}

#[tokio::test]
async fn migration_rejects_a_conflicting_d1_index() {
    let database = Arc::new(MigrationFixtureD1 {
        columns: vec![
            pragma_column("id", "TEXT", true, true),
            pragma_column("label", "TEXT", true, false),
            pragma_column("count", "INTEGER", true, false),
        ],
        index_list: vec![Map::from_iter([
            ("name".into(), json!("counter_label_idx")),
            ("unique".into(), json!(0)),
            ("partial".into(), json!(0)),
        ])],
        index_columns: vec![Map::from_iter([
            ("seqno".into(), json!(0)),
            ("cid".into(), json!(2)),
            ("name".into(), json!("count")),
        ])],
        populated: false,
    });
    let error = D1Store::new(database, D1AdapterConfig::default())
        .migration_plan(schema(), D1MigrationMode::Compile)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("counter_label_idx"));
    assert!(error.to_string().contains("does not match"));
}

#[tokio::test]
async fn programmatic_migration_recognizes_an_existing_d1_index() {
    let database = Arc::new(MigrationFixtureD1 {
        columns: vec![
            pragma_column("id", "TEXT", true, true),
            pragma_column("label", "TEXT", true, false),
            pragma_column("count", "INTEGER", true, false),
        ],
        index_list: vec![Map::from_iter([
            ("name".into(), json!("counter_label_idx")),
            ("unique".into(), json!(0)),
            ("partial".into(), json!(0)),
        ])],
        index_columns: vec![Map::from_iter([
            ("seqno".into(), json!(0)),
            ("cid".into(), json!(1)),
            ("name".into(), json!("label")),
        ])],
        populated: false,
    });
    let plan = D1Store::new(database, D1AdapterConfig::default())
        .migration_plan(schema(), D1MigrationMode::Compile)
        .await
        .unwrap();
    assert!(!plan.compiled_sql().contains("counter_label_idx"));
    assert!(plan.warnings().is_empty());
    assert!(plan.unsafe_changes().is_empty());
}
