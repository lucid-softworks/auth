use chrono::{Duration, Utc};
use lucid_auth::{
    AccessStore, AnonymousPlugin, ApiKeyConfiguration, ApiKeyPlugin, ApiKeySortDirection,
    ApiKeyUpdate, AuthConfig, AuthService, DatabaseIdGeneration, DatabaseIdGenerationRequest,
    DatabaseIdGenerationResult, DatabaseIdGenerationSize as IdSize, DatabaseIdGenerator,
    MemoryStore, NewApiKey, NewPasswordUser, OAuthAccountStore, RateLimitRequest,
    RateLimitStorageMode, SessionWithUser, VerificationValue,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const SECRET: [u8; 32] = [b'I'; 32];

#[derive(Debug, Clone, PartialEq)]
struct CallbackCall {
    model: String,
    size: IdSize,
    id: String,
}

#[derive(Debug, Default)]
struct CallbackLedger {
    calls: Mutex<Vec<CallbackCall>>,
}

impl CallbackLedger {
    fn snapshot(&self) -> Vec<CallbackCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl DatabaseIdGenerator for CallbackLedger {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        let mut calls = self.calls.lock().unwrap();
        let id = format!(
            "opaque::{}::{}::?/+",
            request.model,
            calls.len().saturating_add(1)
        );
        calls.push(CallbackCall {
            model: request.model.into(),
            size: request.size,
            id: id.clone(),
        });
        DatabaseIdGenerationResult::Id(id)
    }
}

struct CoreFixture {
    service: AuthService,
    store: Arc<MemoryStore>,
    ledger: Arc<CallbackLedger>,
    configuration: ApiKeyConfiguration,
    actor: SessionWithUser,
    user_id: String,
    account_id: String,
    session_id: String,
    session_token: String,
    verification_identifier: String,
    verification_id: String,
    api_key_id: String,
    api_key_secret: String,
    rate_limit_request: RateLimitRequest,
}

fn password_user(username: &str) -> NewPasswordUser {
    NewPasswordUser {
        username: username.into(),
        name: "Callback User".into(),
        email: Some(format!("{username}@example.com")),
        password: "correct horse battery staple".into(),
        role: "owner".into(),
    }
}

fn api_key_input() -> NewApiKey {
    NewApiKey {
        config_id: "default".into(),
        name: Some("contract key".into()),
        prefix: None,
        expires_at: None,
        permissions: None,
        metadata: None,
        remaining: Some(10),
        refill_amount: None,
        refill_interval: None,
        rate_limit_enabled: false,
        rate_limit_time_window: None,
        rate_limit_max: None,
    }
}

fn is_base62(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

async fn core_fixture() -> CoreFixture {
    let ledger = Arc::new(CallbackLedger::default());
    let configuration = ApiKeyConfiguration::default();
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.database_id_generation = DatabaseIdGeneration::Callback(ledger.clone());
    config.rate_limit.enabled = true;
    config.rate_limit.storage = RateLimitStorageMode::Database;
    config
        .add_plugin(ApiKeyPlugin::new(configuration.clone()))
        .unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = AuthService::new(store.clone(), config);

    let user = service
        .provision_password_user(password_user("callback_user"))
        .await
        .unwrap();
    let account = store.list_user_accounts(&user.id).await.unwrap().remove(0);
    let signed_in = service
        .sign_in_username(
            "callback_user",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let verification_identifier = "contract:callback".to_owned();
    service
        .create_verification_value(VerificationValue::new(
            &verification_identifier,
            "one-time-value",
            Utc::now() + Duration::minutes(5),
        ))
        .await
        .unwrap();
    let verification = service
        .find_verification_value(&verification_identifier)
        .await
        .unwrap()
        .unwrap();
    let issued = service
        .issue_api_key(&signed_in.session, &configuration, api_key_input())
        .await
        .unwrap();
    let rate_limit_request = RateLimitRequest {
        method: "GET".into(),
        path: "/database-id-contract".into(),
        query: None,
        headers: BTreeMap::new(),
    };
    service
        .consume_rate_limit_request(&rate_limit_request, Some("192.0.2.100"))
        .await
        .unwrap()
        .unwrap();

    CoreFixture {
        service,
        store,
        ledger,
        configuration,
        actor: signed_in.session.clone(),
        user_id: user.id,
        account_id: account.id,
        session_id: signed_in.session.session.id,
        session_token: signed_in.token,
        verification_identifier,
        verification_id: verification.id,
        api_key_id: issued.api_key.id,
        api_key_secret: issued.key,
        rate_limit_request,
    }
}

fn assert_create_callbacks(fixture: &CoreFixture, calls: &[CallbackCall]) {
    assert_eq!(
        calls
            .iter()
            .map(|call| call.model.as_str())
            .collect::<Vec<_>>(),
        [
            "user",
            "account",
            "session",
            "verification",
            "apikey",
            "rateLimit"
        ]
    );
    assert!(calls.iter().all(|call| call.size == IdSize::Omitted));
    assert_eq!(fixture.user_id, calls[0].id);
    assert_eq!(fixture.account_id, calls[1].id);
    assert_eq!(fixture.session_id, calls[2].id);
    assert_eq!(fixture.verification_id, calls[3].id);
    assert_eq!(fixture.api_key_id, calls[4].id);
    assert!(calls.iter().all(|call| call.id.contains("::?/+")));
    assert!(is_base62(&fixture.session_token, 32));
    assert_eq!(fixture.api_key_secret.len(), 64);
    assert!(
        fixture
            .api_key_secret
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic())
    );
}

async fn exercise_read_operations(fixture: &CoreFixture) {
    assert!(
        !fixture
            .service
            .username_available("callback_user")
            .await
            .unwrap()
    );
    assert!(
        fixture
            .service
            .session(&fixture.session_token)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        fixture
            .store
            .list_user_accounts(&fixture.user_id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        fixture
            .service
            .list_passkeys(&fixture.user_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(fixture.store.count_users(&[]).await.unwrap(), 1);
    assert_eq!(fixture.store.count_users_by_role("owner").await.unwrap(), 1);
    assert_eq!(
        fixture
            .service
            .list_api_keys(&fixture.actor, None, None, ApiKeySortDirection::Ascending,)
            .await
            .unwrap()
            .len(),
        1
    );
    fixture
        .service
        .get_api_key(&fixture.actor, &fixture.configuration, &fixture.api_key_id)
        .await
        .unwrap();
    fixture
        .service
        .verify_api_key(
            &fixture.api_key_secret,
            std::slice::from_ref(&fixture.configuration),
            Some("default"),
            None,
        )
        .await
        .unwrap();
}

async fn exercise_update_operations(fixture: &CoreFixture) {
    fixture
        .service
        .update_api_key(
            &fixture.actor,
            &fixture.configuration,
            &fixture.api_key_id,
            ApiKeyUpdate {
                name: Some("renamed contract key".into()),
                ..ApiKeyUpdate::default()
            },
        )
        .await
        .unwrap();
    fixture
        .service
        .update_verification_value(
            &fixture.verification_identifier,
            "updated-value".into(),
            None,
        )
        .await
        .unwrap()
        .unwrap();
    fixture
        .service
        .consume_rate_limit_request(&fixture.rate_limit_request, Some("192.0.2.100"))
        .await
        .unwrap()
        .unwrap();
    fixture
        .service
        .provision_password_user(password_user("callback_user"))
        .await
        .unwrap();
}

async fn exercise_delete_operations(fixture: &CoreFixture) {
    fixture
        .service
        .delete_verification_value(&fixture.verification_identifier)
        .await
        .unwrap()
        .unwrap();
    fixture
        .service
        .delete_api_key(&fixture.actor, &fixture.configuration, &fixture.api_key_id)
        .await
        .unwrap();
    fixture
        .service
        .sign_out(&fixture.session_token)
        .await
        .unwrap();
    assert_eq!(fixture.service.delete_expired_api_keys().await.unwrap(), 0);
}

#[tokio::test]
async fn callbacks_cover_public_core_creates_once_and_leave_bearer_formats_unchanged() {
    let fixture = core_fixture().await;
    let calls = fixture.ledger.snapshot();
    assert_create_callbacks(&fixture, &calls);

    exercise_read_operations(&fixture).await;
    exercise_update_operations(&fixture).await;
    let before_deletes = fixture.ledger.snapshot();
    assert_eq!(before_deletes, calls);

    exercise_delete_operations(&fixture).await;
    assert_eq!(fixture.ledger.snapshot(), before_deletes);
}

#[tokio::test]
async fn default_memory_store_ids_are_32_character_base62_strings() {
    let configuration = ApiKeyConfiguration::default();
    let mut config = AuthConfig::new(SECRET).unwrap();
    config
        .add_plugin(ApiKeyPlugin::new(configuration.clone()))
        .unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = AuthService::new(store.clone(), config);
    let user = service
        .provision_password_user(password_user("default_ids"))
        .await
        .unwrap();
    let account = store.list_user_accounts(&user.id).await.unwrap().remove(0);
    let signed_in = service
        .sign_in_username(
            "default_ids",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    service
        .create_verification_value(VerificationValue::new(
            "contract:default",
            "value",
            Utc::now() + Duration::minutes(5),
        ))
        .await
        .unwrap();
    let verification = service
        .find_verification_value("contract:default")
        .await
        .unwrap()
        .unwrap();
    let issued = service
        .issue_api_key(&signed_in.session, &configuration, api_key_input())
        .await
        .unwrap();

    for id in [
        &user.id,
        &account.id,
        &signed_in.session.session.id,
        &verification.id,
        &issued.api_key.id,
    ] {
        assert!(is_base62(id, 32), "unexpected default database ID: {id}");
    }
}

#[tokio::test]
async fn anonymous_email_entropy_is_independent_from_callback_user_ids() {
    let ledger = Arc::new(CallbackLedger::default());
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.database_id_generation = DatabaseIdGeneration::Callback(ledger.clone());
    config.add_plugin(AnonymousPlugin::default()).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);

    let result = service.sign_in_anonymous(None, None).await.unwrap();
    let calls = ledger.snapshot();
    assert_eq!(
        calls
            .iter()
            .map(|call| call.model.as_str())
            .collect::<Vec<_>>(),
        ["user", "session"]
    );
    assert_eq!(result.session.user.id, calls[0].id);
    assert_eq!(result.session.session.id, calls[1].id);
    assert!(is_base62(&result.token, 32));

    let entropy = result
        .session
        .user
        .email
        .strip_prefix("temp@")
        .and_then(|email| email.strip_suffix(".com"))
        .expect("default anonymous email shape");
    assert!(is_base62(entropy, 32));
    assert_ne!(entropy, result.session.user.id);
    assert!(!result.session.user.email.contains(&result.session.user.id));
}
