use lucid_auth::{
    DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan, DatabaseIdValue, MemoryStore,
    PreparedDatabaseId, generate_database_id,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Oracle {
    better_auth_version: String,
    default_length: usize,
    errors: Errors,
    fixed_uuid: String,
    serial_coercion: Vec<SerialCoercion>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Errors {
    invalid_length: String,
}

#[derive(Debug, Deserialize)]
struct SerialCoercion {
    kind: String,
    value: Value,
    output: Option<f64>,
}

fn oracle() -> Oracle {
    serde_json::from_str(include_str!("../conformance/id-strategy-oracle-1.7.2.json")).unwrap()
}

fn id_input(case: &SerialCoercion) -> DatabaseIdInput {
    match case.kind.as_str() {
        "null" => DatabaseIdInput::Null,
        "boolean" => DatabaseIdInput::Boolean(case.value.as_bool().unwrap()),
        "number" => DatabaseIdInput::Number(case.value.as_f64().unwrap()),
        "string" => DatabaseIdInput::String(case.value.as_str().unwrap().into()),
        "array" => DatabaseIdInput::Array(case.value.as_array().unwrap().clone()),
        kind => panic!("unhandled fixture input kind: {kind}"),
    }
}

#[test]
fn pinned_oracle_drives_builtin_and_serial_id_edges() {
    let oracle = oracle();
    assert_eq!(oracle.better_auth_version, "1.7.2");
    let generated = generate_database_id(lucid_auth::DatabaseIdGenerationSize::Omitted).unwrap();
    assert_eq!(generated.len(), oracle.default_length);
    assert!(generated.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert_eq!(
        generate_database_id(lucid_auth::DatabaseIdGenerationSize::Value(-1.0))
            .unwrap_err()
            .to_string(),
        oracle.errors.invalid_length
    );

    let store = MemoryStore::default();
    for case in &oracle.serial_coercion {
        let prepared =
            DatabaseIdPlan::new(DatabaseIdGeneration::Serial, "user", id_input(case), true)
                .prepare(&store)
                .unwrap();
        match case.output {
            Some(expected) => assert_eq!(
                prepared,
                PreparedDatabaseId::Value(DatabaseIdValue::Number(expected)),
                "fixture case: {case:?}"
            ),
            None => assert_eq!(
                prepared,
                PreparedDatabaseId::DeferredSerial,
                "fixture case: {case:?}"
            ),
        }
    }
}

#[test]
fn pinned_oracle_drives_uuid_and_missing_id_strategy_edges() {
    let oracle = oracle();
    let store = MemoryStore::default();
    let prepare = |strategy, input, forced| {
        DatabaseIdPlan::new(strategy, "user", input, forced)
            .prepare(&store)
            .unwrap()
    };

    assert_eq!(
        prepare(
            DatabaseIdGeneration::Database,
            DatabaseIdInput::Absent,
            false
        ),
        PreparedDatabaseId::Deferred
    );
    assert_eq!(
        prepare(DatabaseIdGeneration::Serial, DatabaseIdInput::Absent, false),
        PreparedDatabaseId::DeferredSerial
    );
    assert_eq!(
        prepare(
            DatabaseIdGeneration::Uuid,
            DatabaseIdInput::String(oracle.fixed_uuid.clone()),
            true,
        ),
        PreparedDatabaseId::Value(DatabaseIdValue::String(oracle.fixed_uuid))
    );
    assert_eq!(
        prepare(
            DatabaseIdGeneration::Uuid,
            DatabaseIdInput::String("not-a-uuid".into()),
            true,
        ),
        PreparedDatabaseId::Deferred
    );
    let generated = prepare(
        DatabaseIdGeneration::Uuid,
        DatabaseIdInput::Array(vec![Value::from(7)]),
        true,
    );
    let PreparedDatabaseId::Value(DatabaseIdValue::String(generated)) = generated else {
        panic!("non-string forced UUID must generate an application UUID")
    };
    uuid::Uuid::parse_str(&generated).unwrap();
}
