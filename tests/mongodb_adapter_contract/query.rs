use crate::support::{replica_store, standalone_store};
use lucid_auth::{
    AdditionalField, AdditionalFieldType, DatabaseSchemaIndex, PluginSchemaTable,
    mongodb::{
        MongoComparisonMode, MongoFilter, MongoFilterConnector, MongoFilterOperator,
        MongoFindOptions, MongoSort, MongoSortDirection, MongoStore,
    },
};
use mongodb::bson::Document;
use serde_json::{Map, Value, json};

fn table() -> PluginSchemaTable {
    PluginSchemaTable::new("counter")
        .index(DatabaseSchemaIndex::new(["name"]).unique(true))
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
        )
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
#[ignore = "requires MongoDB in MONGODB_STANDALONE_URI"]
async fn standalone_executes_values_predicates_indexes_and_atomic_mutations() {
    let store = standalone_store(table()).await;
    for (id, name, value) in [
        ("one", "Alpha", 4),
        ("two", "Beta", 7),
        ("three", "Alpine", 9),
    ] {
        store
            .insert_record("counter", record(id, name, value))
            .await
            .unwrap();
    }
    assert_values(&store).await;
    assert_predicates(&store).await;
    assert_page_and_atomic_mutations(&store).await;
    let indexes = store
        .database()
        .collection::<Document>("counter")
        .list_index_names()
        .await
        .unwrap();
    assert!(indexes.iter().any(|name| name.contains("counter_name")));
}

async fn assert_values(store: &MongoStore) {
    let first = store
        .find_record("counter", &[MongoFilter::equal("id", json!("one"))], &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first["when"], json!("2026-08-27T12:34:56.123Z"));
    assert_eq!(first["metadata"], json!({"nested": true}));
    assert_eq!(first["tags"], json!(["one", "two"]));
}

async fn assert_predicates(store: &MongoStore) {
    for (operator, value, expected) in [
        (MongoFilterOperator::Eq, json!(7), 1),
        (MongoFilterOperator::Ne, json!(7), 2),
        (MongoFilterOperator::Gt, json!(7), 1),
        (MongoFilterOperator::Gte, json!(7), 2),
        (MongoFilterOperator::Lt, json!(7), 1),
        (MongoFilterOperator::Lte, json!(7), 2),
        (MongoFilterOperator::In, json!([4, 9]), 2),
        (MongoFilterOperator::NotIn, json!([4, 9]), 1),
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
    let mut insensitive = filter("name", json!("ALP"), MongoFilterOperator::StartsWith);
    insensitive.mode = MongoComparisonMode::Insensitive;
    assert_eq!(
        store
            .count_records("counter", &[insensitive])
            .await
            .unwrap(),
        2
    );
    assert!(
        store
            .find_record("counter", &[MongoFilter::equal("missing", json!(1))], &[])
            .await
            .is_err()
    );
}

async fn assert_page_and_atomic_mutations(store: &MongoStore) {
    let page = store
        .find_records(
            "counter",
            &[],
            &MongoFindOptions {
                select: vec!["name".into(), "value".into()],
                sort: Some(MongoSort {
                    field: "value".into(),
                    direction: MongoSortDirection::Descending,
                }),
                limit: Some(1),
                offset: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(page[0]["name"], "Beta");

    let filter = [MongoFilter::equal("id", json!("one"))];
    let incremented = store
        .increment_record(
            "counter",
            &filter,
            Map::from_iter([("value".into(), json!(3))]),
            Map::from_iter([("note".into(), json!("updated"))]),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incremented["value"], 7);
    assert!(
        store
            .consume_record("counter", &filter)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .consume_record("counter", &filter)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
#[ignore = "requires a replica set in MONGODB_REPLICA_SET_URI"]
async fn replica_set_transactions_commit_and_roll_back() {
    let store = replica_store(table()).await;
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
                &[MongoFilter::equal("id", json!("rollback"))],
                &[]
            )
            .await
            .unwrap()
            .is_none()
    );

    let mut transaction = store.begin().await.unwrap();
    transaction
        .insert_record("counter", record("commit", "Permanent", 2))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    assert!(
        store
            .find_record("counter", &[MongoFilter::equal("id", json!("commit"))], &[])
            .await
            .unwrap()
            .is_some()
    );
}

#[test]
fn unsupported_operator_keeps_the_upstream_code() {
    let error = MongoFilterOperator::parse("between").unwrap_err();
    assert_eq!(error.code.as_str(), "UNSUPPORTED_OPERATOR");
    assert_eq!(error.message, "Unsupported operator: between");
}

fn filter(field: &str, value: Value, operator: MongoFilterOperator) -> MongoFilter {
    MongoFilter {
        field: field.into(),
        value,
        operator,
        connector: MongoFilterConnector::And,
        mode: MongoComparisonMode::Sensitive,
    }
}
