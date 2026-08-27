use super::*;
use crate::store::{DatabaseIdInput, DatabaseIdPlan};
use crate::{
    DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult,
    DatabaseIdGenerator,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;

#[derive(Debug)]
struct RecordingGenerator {
    models: Arc<Mutex<Vec<String>>>,
}

impl DatabaseIdGenerator for RecordingGenerator {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        let mut models = self.models.lock().unwrap();
        models.push(request.model.to_owned());
        DatabaseIdGenerationResult::Id(format!("{}-{}", request.model, models.len()))
    }
}

fn create<T>(record: T, model: &str, strategy: &DatabaseIdGeneration) -> DatabaseCreate<T> {
    DatabaseCreate::new(
        record,
        DatabaseIdPlan::new(strategy.clone(), model, DatabaseIdInput::Absent, false),
    )
}

#[derive(Clone)]
struct PreparedAccount(DatabaseCreate<OAuthAccount>);

#[async_trait::async_trait]
impl crate::DependentAccountPreparer for PreparedAccount {
    async fn prepare_account(
        &self,
        _context: crate::DependentAccountContext<'_>,
    ) -> Result<crate::DatabaseWrite<OAuthAccount>, AuthError> {
        Ok(crate::DatabaseWrite::Create(self.0.clone()))
    }
}

#[derive(Clone)]
struct RecordingAccountCreate {
    account: DatabaseCreate<OAuthAccount>,
    events: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl crate::DependentAccountPreparer for RecordingAccountCreate {
    async fn prepare_account(
        &self,
        context: crate::DependentAccountContext<'_>,
    ) -> Result<crate::DatabaseWrite<OAuthAccount>, AuthError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("account-hook:{}", context.user.id));
        Ok(crate::DatabaseWrite::Create(self.account.clone()))
    }
}

fn user(email: &str) -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: String::new(),
        username: None,
        display_username: None,
        name: "Test".into(),
        email: email.into(),
        email_verified: false,
        image: None,
        additional_fields: serde_json::Map::new(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}

fn password_user(email: &str, username: &str) -> AuthUser {
    let mut user = user(email);
    user.username = Some(username.to_owned());
    user
}

fn account() -> OAuthAccount {
    let now = Utc::now();
    OAuthAccount {
        id: String::new(),
        user_id: String::new(),
        issuer: "local:credential".into(),
        account_id: "credential".into(),
        provider_id: "credential".into(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: Some("hash".into()),
        additional_fields: serde_json::Map::new(),
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn dependent_account_id_is_prepared_only_after_user_insert_can_succeed() {
    let store = MemoryStore::default();
    store
        .state
        .write()
        .await
        .emails
        .insert("taken@example.com".into(), "existing".into());
    let models = Arc::new(Mutex::new(Vec::new()));
    let strategy = DatabaseIdGeneration::Callback(Arc::new(RecordingGenerator {
        models: models.clone(),
    }));

    let error = create_password(
        &store,
        create(user("taken@example.com"), "user", &strategy),
        &PreparedAccount(create(account(), "account", &strategy)),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, AuthError::UserAlreadyExists));
    assert_eq!(*models.lock().unwrap(), ["user"]);

    create_password(
        &store,
        create(user("new@example.com"), "user", &strategy),
        &PreparedAccount(create(account(), "account", &strategy)),
    )
    .await
    .unwrap();
    assert_eq!(*models.lock().unwrap(), ["user", "user", "account"]);
}

#[tokio::test]
async fn dependent_account_hook_receives_returned_user_id_before_account_callback() {
    let store = MemoryStore::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let strategy = DatabaseIdGeneration::Callback(Arc::new(RecordingGenerator {
        models: events.clone(),
    }));
    let account = RecordingAccountCreate {
        account: create(account(), "account", &strategy),
        events: events.clone(),
    };

    let owner = create_password(
        &store,
        create(user("ordered@example.com"), "user", &strategy),
        &account,
    )
    .await
    .unwrap();

    assert_eq!(
        *events.lock().unwrap(),
        vec![
            "user".to_owned(),
            format!("account-hook:{}", owner.user.id),
            "account".to_owned(),
        ]
    );
    assert_eq!(owner.account.user_id, owner.user.id);
    assert_eq!(owner.account.account_id, owner.user.id);
}

#[derive(Clone)]
struct ContextRecordingPreparer {
    result: crate::DatabaseWrite<OAuthAccount>,
    observed: Arc<Mutex<Vec<ObservedDependentAccountContext>>>,
}

type ObservedDependentAccountContext =
    (String, crate::DatabaseWriteOperation, Option<OAuthAccount>);

#[async_trait::async_trait]
impl crate::DependentAccountPreparer for ContextRecordingPreparer {
    async fn prepare_account(
        &self,
        context: crate::DependentAccountContext<'_>,
    ) -> Result<crate::DatabaseWrite<OAuthAccount>, AuthError> {
        self.observed.lock().unwrap().push((
            context.user.id.clone(),
            context.user_operation,
            context.existing_account.cloned(),
        ));
        Ok(self.result.clone())
    }
}

#[tokio::test]
async fn upsert_passes_persisted_user_and_existing_account_with_exact_update_metadata() {
    let store = MemoryStore::default();
    let strategy = DatabaseIdGeneration::Uuid;
    let owner = create_password(
        &store,
        create(
            password_user("existing@example.com", "existing"),
            "user",
            &strategy,
        ),
        &PreparedAccount(create(account(), "account", &strategy)),
    )
    .await
    .unwrap();
    let mut updated_user = owner.user.clone();
    updated_user.name = "Updated".into();
    let mut updated_account = owner.account.clone();
    updated_account.password = Some("new-hash".into());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let preparer = ContextRecordingPreparer {
        result: crate::DatabaseWrite::Update(updated_account),
        observed: observed.clone(),
    };

    let write = upsert_password(
        &store,
        crate::DatabaseWrite::Update(updated_user),
        &preparer,
    )
    .await
    .unwrap();

    assert_eq!(write.user_operation, crate::DatabaseWriteOperation::Update);
    assert_eq!(
        write.account_operation,
        crate::DatabaseWriteOperation::Update
    );
    assert_eq!(write.owner.user.name, "Updated");
    let observed = observed.lock().unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].0, owner.user.id);
    assert_eq!(observed[0].1, crate::DatabaseWriteOperation::Update);
    assert_eq!(
        observed[0].2.as_ref().map(|account| &account.id),
        Some(&owner.account.id)
    );
}

#[tokio::test]
async fn upsert_reports_account_create_when_existing_user_has_no_credential_account() {
    let store = MemoryStore::default();
    let strategy = DatabaseIdGeneration::Uuid;
    let stored = create_without_account(
        &store,
        create(
            password_user("accountless@example.com", "accountless"),
            "user",
            &strategy,
        ),
    )
    .await
    .unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let preparer = ContextRecordingPreparer {
        result: crate::DatabaseWrite::Create(create(account(), "account", &strategy)),
        observed: observed.clone(),
    };

    let write = upsert_password(
        &store,
        crate::DatabaseWrite::Update(stored.clone()),
        &preparer,
    )
    .await
    .unwrap();

    assert_eq!(write.user_operation, crate::DatabaseWriteOperation::Update);
    assert_eq!(
        write.account_operation,
        crate::DatabaseWriteOperation::Create
    );
    assert_eq!(write.owner.account.user_id, stored.id);
    assert!(observed.lock().unwrap()[0].2.is_none());
}

#[derive(Clone)]
struct FailingPreparer;

#[async_trait::async_trait]
impl crate::DependentAccountPreparer for FailingPreparer {
    async fn prepare_account(
        &self,
        _context: crate::DependentAccountContext<'_>,
    ) -> Result<crate::DatabaseWrite<OAuthAccount>, AuthError> {
        Err(AuthError::Storage("account hook failed".into()))
    }
}

#[tokio::test]
async fn failed_preparation_releases_pending_keys_without_retrying_callbacks() {
    let store = MemoryStore::default();
    let models = Arc::new(Mutex::new(Vec::new()));
    let strategy = DatabaseIdGeneration::Callback(Arc::new(RecordingGenerator {
        models: models.clone(),
    }));

    let error = create_password(
        &store,
        create(
            password_user("retry@example.com", "retry"),
            "user",
            &strategy,
        ),
        &FailingPreparer,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, AuthError::Storage(_)));

    create_password(
        &store,
        create(
            password_user("retry@example.com", "retry"),
            "user",
            &strategy,
        ),
        &PreparedAccount(create(account(), "account", &strategy)),
    )
    .await
    .unwrap();
    assert_eq!(*models.lock().unwrap(), ["user", "user", "account"]);
}

#[derive(Clone)]
struct BlockingPreparer {
    account: DatabaseCreate<OAuthAccount>,
    started: Arc<Notify>,
    release: Arc<Notify>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::DependentAccountPreparer for BlockingPreparer {
    async fn prepare_account(
        &self,
        _context: crate::DependentAccountContext<'_>,
    ) -> Result<crate::DatabaseWrite<OAuthAccount>, AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        self.release.notified().await;
        Ok(crate::DatabaseWrite::Create(self.account.clone()))
    }
}

#[tokio::test]
async fn concurrent_duplicate_is_rejected_while_hook_runs_without_callback_retry() {
    let store = MemoryStore::default();
    let strategy = DatabaseIdGeneration::Uuid;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let preparer = BlockingPreparer {
        account: create(account(), "account", &strategy),
        started: started.clone(),
        release: release.clone(),
        calls: calls.clone(),
    };
    let first_store = store.clone();
    let first_strategy = strategy.clone();
    let first = tokio::spawn(async move {
        create_password(
            &first_store,
            create(
                password_user("racing@example.com", "racing"),
                "user",
                &first_strategy,
            ),
            &preparer,
        )
        .await
    });
    started.notified().await;

    let second = create_password(
        &store,
        create(
            password_user("racing@example.com", "racing"),
            "user",
            &strategy,
        ),
        &PreparedAccount(create(account(), "account", &strategy)),
    )
    .await;
    assert!(matches!(
        second,
        Err(AuthError::UserAlreadyExists) | Err(AuthError::Username(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    release.notify_one();
    first.await.unwrap().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
