use crate::mssql::MssqlStore;
use serde_json::{Map, Value, json};

pub(super) fn record(id: Option<&str>, name: &str, value: i64) -> Map<String, Value> {
    let mut record = Map::from_iter([
        ("name".into(), json!(name)),
        ("value".into(), json!(value)),
        ("active".into(), json!(true)),
        ("when".into(), json!("2026-08-31T12:34:56.123456Z")),
        ("metadata".into(), json!({"nested": true})),
        ("tags".into(), json!(["one", "two"])),
        ("note".into(), Value::Null),
        ("groupId".into(), Value::Null),
    ]);
    if let Some(id) = id {
        record.insert("id".into(), json!(id));
    }
    record
}

pub(super) async fn seed(store: &MssqlStore) -> Map<String, Value> {
    store
        .insert_record(
            "group",
            Map::from_iter([
                ("id".into(), json!("group-one")),
                ("name".into(), json!("Example")),
            ]),
        )
        .await
        .unwrap();
    let inserted = store
        .insert_record("counter", record(Some("one"), "Alpha", 4))
        .await
        .unwrap()
        .unwrap();
    for (id, name, value) in [("two", "Beta", 7), ("three", "Alpine", 9)] {
        let mut value_record = record(Some(id), name, value);
        value_record.insert("groupId".into(), json!("group-one"));
        store
            .insert_record("counter", value_record)
            .await
            .unwrap();
    }
    inserted
}
