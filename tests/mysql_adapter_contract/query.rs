use crate::support::catalog;
use crate::support::pool;
use lucid_auth::{
    AdditionalField, AdditionalFieldType, AuthError, DashAdapterWhere, PluginSchemaTable,
    mysql::{
        MySqlAdapterConfig, MySqlComparisonMode, MySqlFilter, MySqlFilterConnector,
        MySqlFilterOperator, MySqlFindOptions, MySqlMigrationMode, MySqlSort, MySqlSortDirection,
        MySqlStore,
    },
    run_database_transaction,
};
use serde_json::{Map, Value, json};

async fn store() -> MySqlStore {
    let store = MySqlStore::new(pool(4).await, MySqlAdapterConfig::default());
    let table = PluginSchemaTable::new("counter")
        .field("name", AdditionalField::new(AdditionalFieldType::String))
        .field("value", AdditionalField::new(AdditionalFieldType::Number))
        .field("active", AdditionalField::new(AdditionalFieldType::Boolean))
        .field("when", AdditionalField::new(AdditionalFieldType::Date))
        .field("metadata", AdditionalField::new(AdditionalFieldType::Json))
        .field(
            "tags",
            AdditionalField::new(AdditionalFieldType::StringArray),
        )
        .field(
            "note",
            AdditionalField::new(AdditionalFieldType::String).optional(),
        );
    store.migrate(catalog(table, [62; 32])).await.unwrap();
    store
}

fn record(id: &str, name: &str, value: i64) -> Map<String, Value> {
    Map::from_iter([
        ("id".into(), json!(id)),
        ("name".into(), json!(name)),
        ("value".into(), json!(value)),
        ("active".into(), json!(true)),
        ("when".into(), json!("2026-08-27T12:34:56.123456Z")),
        ("metadata".into(), json!({"nested": true})),
        ("tags".into(), json!(["one", "two"])),
        ("note".into(), Value::Null),
    ])
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn round_trips_schema_values_and_bound_predicates() {
    let store = store().await;
    let inserted = store
        .insert_record("counter", record("one", "Alpha", 4))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inserted["when"], json!("2026-08-27T12:34:56.123Z"));
    assert_eq!(inserted["metadata"], json!({"nested": true}));
    assert_eq!(inserted["tags"], json!(["one", "two"]));

    let insensitive = MySqlFilter {
        field: "name".into(),
        value: json!("ALP"),
        operator: MySqlFilterOperator::Contains,
        connector: MySqlFilterConnector::And,
        mode: MySqlComparisonMode::Insensitive,
    };
    assert_eq!(
        store
            .count_records("counter", &[insensitive])
            .await
            .unwrap(),
        1
    );
    assert!(
        store
            .find_record(
                "counter",
                &[MySqlFilter::equal("missing", json!("value"))],
                &[],
            )
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn supports_every_predicate_grouping_selection_sorting_and_pagination() {
    let store = store().await;
    for (id, name, value, note) in [
        ("one", "Alpha", 4, None),
        ("two", "Beta", 7, Some("second")),
        ("three", "Alpine", 9, Some("third")),
    ] {
        let mut value_record = record(id, name, value);
        value_record.insert("note".into(), json!(note));
        store.insert_record("counter", value_record).await.unwrap();
    }

    for (operator, value, expected) in [
        (MySqlFilterOperator::Eq, json!(7), 1),
        (MySqlFilterOperator::Ne, json!(7), 2),
        (MySqlFilterOperator::Gt, json!(7), 1),
        (MySqlFilterOperator::Gte, json!(7), 2),
        (MySqlFilterOperator::Lt, json!(7), 1),
        (MySqlFilterOperator::Lte, json!(7), 2),
        (MySqlFilterOperator::In, json!([4, 9]), 2),
        (MySqlFilterOperator::NotIn, json!([4, 9]), 1),
    ] {
        assert_eq!(
            store
                .count_records("counter", &[filter("value", value, operator)])
                .await
                .unwrap(),
            expected,
            "operator {operator:?}",
        );
    }
    for (operator, value, expected) in [
        (MySqlFilterOperator::Contains, json!("ph"), 1),
        (MySqlFilterOperator::StartsWith, json!("Al"), 2),
        (MySqlFilterOperator::EndsWith, json!("ta"), 1),
    ] {
        assert_eq!(
            store
                .count_records("counter", &[filter("name", value, operator)])
                .await
                .unwrap(),
            expected,
            "operator {operator:?}",
        );
    }
    assert_eq!(
        store
            .count_records(
                "counter",
                &[
                    filter("note", Value::Null, MySqlFilterOperator::Eq),
                    filter("value", json!(5), MySqlFilterOperator::Gt),
                ],
            )
            .await
            .unwrap(),
        0,
    );
    assert_eq!(
        store
            .count_records(
                "counter",
                &[
                    filter("note", Value::Null, MySqlFilterOperator::Ne),
                    filter("value", json!(5), MySqlFilterOperator::Gt),
                ],
            )
            .await
            .unwrap(),
        2,
    );

    let mut insensitive = filter("name", json!(["ALPHA", "NOPE"]), MySqlFilterOperator::In);
    insensitive.mode = MySqlComparisonMode::Insensitive;
    assert_eq!(
        store
            .count_records("counter", &[insensitive])
            .await
            .unwrap(),
        1
    );
    let grouped = [
        filter("value", json!(5), MySqlFilterOperator::Gt),
        with_connector(
            filter("name", json!("Al"), MySqlFilterOperator::StartsWith),
            MySqlFilterConnector::Or,
        ),
    ];
    assert_eq!(store.count_records("counter", &grouped).await.unwrap(), 1);

    let page = store
        .find_records(
            "counter",
            &[],
            &MySqlFindOptions {
                select: vec!["name".into(), "value".into()],
                sort: Some(MySqlSort {
                    field: "value".into(),
                    direction: MySqlSortDirection::Descending,
                }),
                limit: Some(1),
                offset: Some(1),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        page,
        vec![Map::from_iter([
            ("name".into(), json!("Beta")),
            ("value".into(), json!(7))
        ])]
    );
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn atomic_increment_and_consume_return_each_row_once() {
    let store = store().await;
    store
        .insert_record("counter", record("one", "Alpha", 4))
        .await
        .unwrap();
    let filters = [MySqlFilter::equal("id", json!("one"))];
    let updated = store
        .increment_record(
            "counter",
            &filters,
            Map::from_iter([("value".into(), json!(3))]),
            Map::from_iter([("note".into(), json!("updated"))]),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated["value"], json!(7));
    assert_eq!(updated["note"], json!("updated"));
    assert!(
        store
            .consume_record("counter", &filters)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .consume_record("counter", &filters)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn separate_connections_serialize_increment_and_consume() {
    let store = store().await;
    store
        .insert_record("counter", record("counter", "Concurrent", 0))
        .await
        .unwrap();
    let mut increments = Vec::new();
    for _ in 0..12 {
        let store = store.clone();
        increments.push(tokio::spawn(async move {
            store
                .increment_record(
                    "counter",
                    &[MySqlFilter::equal("id", json!("counter"))],
                    Map::from_iter([("value".into(), json!(1))]),
                    Map::new(),
                )
                .await
        }));
    }
    for increment in increments {
        increment.await.unwrap().unwrap().unwrap();
    }
    assert_eq!(
        store
            .find_record(
                "counter",
                &[MySqlFilter::equal("id", json!("counter"))],
                &[],
            )
            .await
            .unwrap()
            .unwrap()["value"],
        12,
    );

    let mut consumers = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        consumers.push(tokio::spawn(async move {
            store
                .consume_record("counter", &[MySqlFilter::equal("id", json!("counter"))])
                .await
        }));
    }
    let mut consumed = 0;
    for consumer in consumers {
        consumed += usize::from(consumer.await.unwrap().unwrap().is_some());
    }
    assert_eq!(consumed, 1);
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn explicit_transaction_rolls_back_without_store_policy() {
    let store = store().await;
    let mut transaction = store.begin().await.unwrap();
    transaction
        .insert_record("counter", record("rollback", "Temporary", 1))
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    assert!(
        store
            .find_record(
                "counter",
                &[MySqlFilter::equal("id", json!("rollback"))],
                &[],
            )
            .await
            .unwrap()
            .is_none()
    );

    let empty = store
        .migration_plan(
            catalog(
                PluginSchemaTable::new("counter")
                    .field("name", AdditionalField::new(AdditionalFieldType::String))
                    .field("value", AdditionalField::new(AdditionalFieldType::Number))
                    .field("active", AdditionalField::new(AdditionalFieldType::Boolean))
                    .field("when", AdditionalField::new(AdditionalFieldType::Date))
                    .field("metadata", AdditionalField::new(AdditionalFieldType::Json))
                    .field(
                        "tags",
                        AdditionalField::new(AdditionalFieldType::StringArray),
                    )
                    .field(
                        "note",
                        AdditionalField::new(AdditionalFieldType::String).optional(),
                    ),
                [62; 32],
            ),
            MySqlMigrationMode::Compile,
        )
        .await
        .unwrap();
    assert_eq!(empty.compiled_sql(), ";");
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn logical_plugin_rows_use_the_public_native_transaction() {
    let store = store().await;
    let updated = run_database_transaction(&store, |transaction| {
        Box::pin(async move {
            transaction
                .create_record("counter", record("native", "Native", 4))
                .await?;
            transaction
                .increment_record(
                    "counter",
                    &[equal("id", json!("native"))],
                    Map::from_iter([("value".into(), json!(3))]),
                    Map::from_iter([("note".into(), json!("committed"))]),
                )
                .await?
                .ok_or(AuthError::NotFound)
        })
    })
    .await
    .unwrap();
    assert_eq!(updated["value"], 7);
    assert_eq!(updated["note"], "committed");

    let error = run_database_transaction::<(), _>(&store, |transaction| {
        Box::pin(async move {
            transaction
                .update_record(
                    "counter",
                    &[equal("id", json!("native"))],
                    Map::from_iter([("value".into(), json!(99))]),
                )
                .await?;
            Err(AuthError::Storage("rollback".into()))
        })
    })
    .await
    .unwrap_err();
    assert!(matches!(error, AuthError::Storage(message) if message == "rollback"));
    assert_eq!(
        store
            .find_record("counter", &[MySqlFilter::equal("id", json!("native"))], &[],)
            .await
            .unwrap()
            .unwrap()["value"],
        7
    );
}

fn equal(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: Default::default(),
        connector: None,
    }
}

fn filter(field: &str, value: Value, operator: MySqlFilterOperator) -> MySqlFilter {
    MySqlFilter {
        field: field.into(),
        value,
        operator,
        connector: MySqlFilterConnector::And,
        mode: MySqlComparisonMode::Sensitive,
    }
}

fn with_connector(mut filter: MySqlFilter, connector: MySqlFilterConnector) -> MySqlFilter {
    filter.connector = connector;
    filter
}
