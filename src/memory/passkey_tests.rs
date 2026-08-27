use super::*;
use crate::store::{DatabaseCreate, DatabaseIdInput, DatabaseIdPlan};
use crate::{
    DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult,
    DatabaseIdGenerationSize, DatabaseIdGenerator, PasskeyDeleteOutcome,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
struct CountingGenerator(Arc<AtomicUsize>);

impl DatabaseIdGenerator for CountingGenerator {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        assert_eq!(request.model, "passkey");
        assert_eq!(request.size, DatabaseIdGenerationSize::Omitted);
        self.0.fetch_add(1, Ordering::SeqCst);
        DatabaseIdGenerationResult::Id("callback-passkey".into())
    }
}

#[derive(Debug)]
struct EmptyGenerator;

impl DatabaseIdGenerator for EmptyGenerator {
    fn generate(&self, _: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        DatabaseIdGenerationResult::Id(String::new())
    }
}

#[derive(Debug)]
struct DeferringGenerator;

impl DatabaseIdGenerator for DeferringGenerator {
    fn generate(&self, _: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        DatabaseIdGenerationResult::Defer
    }
}

fn passkey(credential_id: &str) -> StoredPasskey {
    StoredPasskey {
        id: String::new(),
        user_id: "user".into(),
        name: None,
        credential_id: credential_id.into(),
        public_key: "public-key".into(),
        counter: 0,
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: None,
        aaguid: None,
        created_at: Utc::now(),
    }
}

fn create(record: StoredPasskey, strategy: DatabaseIdGeneration) -> DatabaseCreate<StoredPasskey> {
    DatabaseCreate::new(
        record,
        DatabaseIdPlan::new(strategy, "passkey", DatabaseIdInput::Absent, false),
    )
}

#[tokio::test]
async fn duplicate_credential_does_not_consume_passkey_id_callback() {
    let store = MemoryStore::default();
    store
        .save_passkey(create(
            passkey("same-credential"),
            DatabaseIdGeneration::Uuid,
        ))
        .await
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));

    let result = store
        .save_passkey(create(
            passkey("same-credential"),
            DatabaseIdGeneration::Callback(Arc::new(CountingGenerator(calls.clone()))),
        ))
        .await;

    assert!(matches!(
        result,
        Err(AuthError::CredentialAlreadyRegistered)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

async fn assert_strategy_crud(strategy: DatabaseIdGeneration, credential: &str) -> String {
    let store = MemoryStore::default();
    let stored = store
        .save_passkey(create(passkey(credential), strategy))
        .await
        .unwrap();
    assert_eq!(
        store.find_passkey_by_id(&stored.id).await.unwrap(),
        Some(stored.clone())
    );
    assert_eq!(
        store.list_passkeys("user").await.unwrap(),
        std::slice::from_ref(&stored)
    );
    let renamed = store
        .update_passkey_name("user", &stored.id, "renamed".into())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(renamed.name.as_deref(), Some("renamed"));
    assert_eq!(
        store.delete_passkey("user", &stored.id, 0).await.unwrap(),
        PasskeyDeleteOutcome::Deleted { remaining: 0 }
    );
    assert!(
        store
            .find_passkey_by_id(&stored.id)
            .await
            .unwrap()
            .is_none()
    );
    stored.id
}

#[tokio::test]
async fn every_application_strategy_round_trips_opaque_passkey_ids() {
    let default = assert_strategy_crud(DatabaseIdGeneration::Default, "default").await;
    assert_eq!(default.len(), 32);
    assert!(default.bytes().all(|byte| byte.is_ascii_alphanumeric()));

    let uuid = assert_strategy_crud(DatabaseIdGeneration::Uuid, "uuid").await;
    assert_eq!(uuid::Uuid::parse_str(&uuid).unwrap().to_string(), uuid);

    let calls = Arc::new(AtomicUsize::new(0));
    let callback = assert_strategy_crud(
        DatabaseIdGeneration::Callback(Arc::new(CountingGenerator(calls.clone()))),
        "callback",
    )
    .await;
    assert_eq!(callback, "callback-passkey");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    assert_eq!(
        assert_strategy_crud(DatabaseIdGeneration::Serial, "serial").await,
        "1"
    );
}

#[tokio::test]
async fn every_ordinary_deferred_passkey_id_is_rejected_by_memory() {
    for (strategy, credential) in [
        (DatabaseIdGeneration::Database, "database"),
        (
            DatabaseIdGeneration::Callback(Arc::new(DeferringGenerator)),
            "callback-false",
        ),
        (
            DatabaseIdGeneration::Callback(Arc::new(EmptyGenerator)),
            "callback-empty",
        ),
    ] {
        let error = MemoryStore::default()
            .save_passkey(create(passkey(credential), strategy))
            .await
            .unwrap_err();
        assert!(
            matches!(error, AuthError::Storage(message) if message.contains("model 'passkey'"))
        );
    }
}
