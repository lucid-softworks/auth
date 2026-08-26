use super::*;
use crate::store::{DatabaseCreate, DatabaseIdInput, DatabaseIdPlan};
use crate::{
    DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult,
    DatabaseIdGenerator,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
struct CountingGenerator(Arc<AtomicUsize>);

impl DatabaseIdGenerator for CountingGenerator {
    fn generate(&self, _request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        self.0.fetch_add(1, Ordering::SeqCst);
        DatabaseIdGenerationResult::Id("callback-passkey".into())
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
