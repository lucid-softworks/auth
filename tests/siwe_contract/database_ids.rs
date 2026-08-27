use super::{ADDRESS, Verifier};
use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, DatabaseIdGeneration, DatabaseIdGenerationRequest,
    DatabaseIdGenerationResult, DatabaseIdGenerationSize, DatabaseIdGenerator, MemoryStore,
    NewPasswordUser, SiweConfig, SiweNonceGenerator, SiwePlugin, SiweSchema, SiweStore,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Clone, PartialEq)]
struct IdCall {
    model: String,
    size: DatabaseIdGenerationSize,
    id: String,
}

#[derive(Debug, Default)]
struct IdLedger {
    calls: Mutex<Vec<IdCall>>,
    fixed_wallet_id: bool,
}

impl IdLedger {
    fn calls_for(&self, model: &str) -> Vec<IdCall> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.model == model)
            .cloned()
            .collect()
    }
}

impl DatabaseIdGenerator for IdLedger {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        let mut calls = self.calls.lock().unwrap();
        let occurrence = calls
            .iter()
            .filter(|call| call.model == request.model)
            .count()
            .saturating_add(1);
        let id = if self.fixed_wallet_id && request.model == "walletAddress" {
            "fixed::walletAddress::?/+".to_owned()
        } else {
            format!("opaque::{}::{occurrence}::?/+", request.model)
        };
        calls.push(IdCall {
            model: request.model.into(),
            size: request.size,
            id: id.clone(),
        });
        DatabaseIdGenerationResult::Id(id)
    }
}

struct Nonce(AtomicUsize);

#[async_trait]
impl SiweNonceGenerator for Nonce {
    async fn generate(&self) -> Result<String, AuthError> {
        Ok(format!(
            "nonce{:08}",
            self.0.fetch_add(1, Ordering::Relaxed)
        ))
    }
}

fn service(fixed_wallet_id: bool) -> (AuthService, Arc<MemoryStore>, Arc<IdLedger>) {
    let ledger = Arc::new(IdLedger {
        fixed_wallet_id,
        ..IdLedger::default()
    });
    let (service, store) = service_for_strategy(DatabaseIdGeneration::Callback(ledger.clone()));
    (service, store, ledger)
}

fn service_for_strategy(strategy: DatabaseIdGeneration) -> (AuthService, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::default());
    let mut siwe = SiweConfig::new(
        "example.com",
        Arc::new(Nonce(AtomicUsize::new(1))),
        Arc::new(Verifier),
    );
    siwe.anonymous = true;
    siwe.email_domain_name = Some("example.com".into());
    let mut config = AuthConfig::new([131_u8; 32]).unwrap();
    config.database_id_generation = strategy;
    config
        .add_plugin(SiwePlugin::new(store.clone(), siwe))
        .unwrap();
    (AuthService::new(store.clone(), config), store)
}

async fn verify(service: &AuthService, chain_id: u64) -> Result<(), AuthError> {
    let nonce = service.create_siwe_nonce().await?;
    service
        .verify_siwe_message(
            message(&nonce, chain_id),
            "0xsigned".into(),
            None,
            None,
            None,
            None,
        )
        .await
        .map(|_| ())
}

fn message(nonce: &str, chain_id: u64) -> String {
    format!(
        "example.com wants you to sign in with your Ethereum account:\n{ADDRESS}\n\n\
         URI: https://example.com\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\n\
         Issued At: 2026-08-24T12:00:00Z"
    )
}

#[tokio::test]
async fn wallet_callback_uses_the_canonical_model_once_per_actual_insert() {
    let (service, store, ledger) = service(false);
    verify(&service, 1).await.unwrap();
    let first = store
        .find_wallet_owner(&SiweSchema::default(), ADDRESS, Some(1.0))
        .await
        .unwrap()
        .unwrap();
    let calls = ledger.calls_for("walletAddress");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].model, "walletAddress");
    assert_eq!(calls[0].size, DatabaseIdGenerationSize::Omitted);
    assert_eq!(first.wallet.id, calls[0].id);

    verify(&service, 1).await.unwrap();
    assert_eq!(ledger.calls_for("walletAddress").len(), 1);

    verify(&service, 137).await.unwrap();
    let calls = ledger.calls_for("walletAddress");
    assert_eq!(calls.len(), 2);
    let second = store
        .find_wallet_owner(&SiweSchema::default(), ADDRESS, Some(137.0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.wallet.id, calls[1].id);
    assert_ne!(first.wallet.id, second.wallet.id);
}

#[tokio::test]
async fn duplicate_memory_wallet_ids_fail_atomically_before_account_id_generation() {
    let (service, store, ledger) = service(true);
    verify(&service, 1).await.unwrap();
    assert!(verify(&service, 137).await.is_err());

    assert!(
        store
            .find_wallet_owner(&SiweSchema::default(), ADDRESS, Some(137.0))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(ledger.calls_for("walletAddress").len(), 2);
    assert_eq!(ledger.calls_for("account").len(), 1);
}

#[tokio::test]
async fn rejected_email_conflict_does_not_consume_a_user_id_callback() {
    let (service, _, ledger) = service(false);
    service
        .provision_password_user(NewPasswordUser {
            username: "existing_wallet_email".into(),
            name: "Existing Wallet Email".into(),
            email: Some(format!("{ADDRESS}@example.com").to_lowercase()),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
    let before = ledger.calls_for("user");
    assert_eq!(before.len(), 1);

    assert!(verify(&service, 1).await.is_err());
    assert_eq!(ledger.calls_for("user"), before);
    assert!(ledger.calls_for("walletAddress").is_empty());
}

async fn generated_wallet_id(strategy: DatabaseIdGeneration) -> String {
    let (service, store) = service_for_strategy(strategy);
    verify(&service, 1).await.unwrap();
    store
        .find_wallet_owner(&SiweSchema::default(), ADDRESS, Some(1.0))
        .await
        .unwrap()
        .unwrap()
        .wallet
        .id
}

#[tokio::test]
async fn memory_round_trips_every_builtin_wallet_id_strategy() {
    let default = generated_wallet_id(DatabaseIdGeneration::Default).await;
    assert_eq!(default.len(), 32);
    assert!(default.bytes().all(|byte| byte.is_ascii_alphanumeric()));

    let uuid = generated_wallet_id(DatabaseIdGeneration::Uuid).await;
    assert_eq!(uuid::Uuid::parse_str(&uuid).unwrap().to_string(), uuid);

    assert_eq!(generated_wallet_id(DatabaseIdGeneration::Serial).await, "1");
}
