use super::support::{RecordingAdapter, fixture_configured};
use lucid_auth::{
    DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult,
    DatabaseIdGenerationSize, DatabaseIdGenerator, JwtAdapterContext, JwtConfig,
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct IdLedger {
    calls: Mutex<Vec<(String, DatabaseIdGenerationSize)>>,
}

impl IdLedger {
    fn calls(&self) -> Vec<(String, DatabaseIdGenerationSize)> {
        self.calls.lock().unwrap().clone()
    }
}

impl DatabaseIdGenerator for IdLedger {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        self.calls
            .lock()
            .unwrap()
            .push((request.model.into(), request.size));
        DatabaseIdGenerationResult::Id("callback-jwks-id".into())
    }
}

#[tokio::test]
async fn default_jwk_creation_uses_the_canonical_ordinary_id_strategy() {
    let ledger = Arc::new(IdLedger::default());
    let fixture = fixture_configured(JwtConfig::default(), |config| {
        config.database_id_generation = DatabaseIdGeneration::Callback(ledger.clone());
    });
    let key = fixture
        .service
        .jwt()
        .unwrap()
        .create_jwk(&JwtAdapterContext::default(), None)
        .await
        .unwrap();
    assert_eq!(key.id, "callback-jwks-id");
    assert_eq!(
        ledger.calls(),
        [("jwks".into(), DatabaseIdGenerationSize::Omitted)]
    );
}

#[tokio::test]
async fn memory_jwk_ids_honor_default_uuid_serial_and_database_strategies() {
    for (strategy, expected) in [
        (DatabaseIdGeneration::Default, None),
        (DatabaseIdGeneration::Uuid, Some("uuid")),
        (DatabaseIdGeneration::Serial, Some("1")),
    ] {
        let fixture = fixture_configured(JwtConfig::default(), |config| {
            config.database_id_generation = strategy;
        });
        let key = fixture
            .service
            .jwt()
            .unwrap()
            .create_jwk(&JwtAdapterContext::default(), None)
            .await
            .unwrap();
        match expected {
            None => assert_base62(&key.id, 32),
            Some("uuid") => assert!(uuid::Uuid::parse_str(&key.id).is_ok()),
            Some(expected) => assert_eq!(key.id, expected),
        }
    }

    let fixture = fixture_configured(JwtConfig::default(), |config| {
        config.database_id_generation = DatabaseIdGeneration::Database;
    });
    let error = fixture
        .service
        .jwt()
        .unwrap()
        .create_jwk(&JwtAdapterContext::default(), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("jwks"));
}

#[tokio::test]
async fn custom_create_jwk_owns_its_id_without_consuming_the_database_callback() {
    let ledger = Arc::new(IdLedger::default());
    let adapter = Arc::new(RecordingAdapter::default());
    let jwt = JwtConfig {
        adapter: adapter.config(),
        ..JwtConfig::default()
    };
    let fixture = fixture_configured(jwt, |config| {
        config.database_id_generation = DatabaseIdGeneration::Callback(ledger.clone());
    });
    let key = fixture
        .service
        .jwt()
        .unwrap()
        .create_jwk(&JwtAdapterContext::default(), None)
        .await
        .unwrap();
    assert_eq!(key.id, "recorded-1");
    assert!(ledger.calls().is_empty());
}

fn assert_base62(value: &str, length: usize) {
    assert_eq!(value.len(), length);
    assert!(value.bytes().all(|byte| byte.is_ascii_alphanumeric()));
}
