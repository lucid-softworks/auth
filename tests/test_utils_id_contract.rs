use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, BeforeDatabaseCreateHook, DatabaseCreatePatch,
    DatabaseCreateRecord, DatabaseHookContext, DatabaseHooks, DatabaseIdGeneration,
    DatabaseIdGenerationRequest, DatabaseIdGenerationResult, DatabaseIdGenerationSize,
    DatabaseIdInput, DatabaseModel, MemoryStore, TestUserOverrides, TestUtilsPlugin,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

const SECRET: [u8; 32] = [b'T'; 32];

#[derive(Debug, Clone, PartialEq)]
struct CallbackCall {
    model: String,
    size: DatabaseIdGenerationSize,
    id: Option<String>,
}

#[derive(Debug)]
struct SequenceGenerator {
    results: Mutex<VecDeque<DatabaseIdGenerationResult>>,
    calls: Mutex<Vec<CallbackCall>>,
}

impl SequenceGenerator {
    fn new(results: impl IntoIterator<Item = DatabaseIdGenerationResult>) -> Self {
        Self {
            results: Mutex::new(results.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<CallbackCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl lucid_auth::DatabaseIdGenerator for SequenceGenerator {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        let result = self
            .results
            .lock()
            .unwrap()
            .pop_front()
            .expect("the test provides one result per callback");
        self.calls.lock().unwrap().push(CallbackCall {
            model: request.model.into(),
            size: request.size,
            id: match &result {
                DatabaseIdGenerationResult::Id(id) => Some(id.clone()),
                DatabaseIdGenerationResult::Defer => None,
            },
        });
        result
    }
}

#[derive(Debug, Default)]
struct TestCreateHook {
    seen: Mutex<Vec<(DatabaseIdInput, Option<&'static str>)>>,
}

#[async_trait]
impl DatabaseHooks for TestCreateHook {
    async fn before_create(
        &self,
        record: &DatabaseCreateRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseCreateHook, AuthError> {
        if record.model() != DatabaseModel::User {
            return Ok(BeforeDatabaseCreateHook::Continue);
        }
        assert!(record.has_id());
        self.seen
            .lock()
            .unwrap()
            .push((record.id().clone(), context.creation_method));
        Ok(BeforeDatabaseCreateHook::merge(
            DatabaseCreatePatch::new()
                .with_id(DatabaseIdInput::String("hook::forced-user::?/+".into())),
        ))
    }
}

#[test]
fn factory_callbacks_run_before_overrides_and_only_literal_false_falls_back() {
    let generator = Arc::new(SequenceGenerator::new([
        DatabaseIdGenerationResult::Id("discarded-for-truthy".into()),
        DatabaseIdGenerationResult::Id("discarded-for-empty".into()),
        DatabaseIdGenerationResult::Id(String::new()),
        DatabaseIdGenerationResult::Defer,
        DatabaseIdGenerationResult::Defer,
    ]));
    let service = service(generator.clone());
    let helpers = service.test().unwrap();

    let truthy = helpers.create_user(TestUserOverrides {
        id: Some("explicit::user::?/+".into()),
        ..TestUserOverrides::default()
    });
    let empty_override = helpers.create_user(TestUserOverrides {
        id: Some(String::new()),
        ..TestUserOverrides::default()
    });
    let empty_callback = helpers.create_user(TestUserOverrides::default());
    let false_callback = helpers.create_user(TestUserOverrides::default());
    let second_false_callback = helpers.create_user(TestUserOverrides::default());

    assert_eq!(truthy.id, "explicit::user::?/+");
    assert!(empty_override.id.is_empty());
    assert!(empty_callback.id.is_empty());
    assert!(is_base62(&false_callback.id, 24));
    assert!(is_base62(&second_false_callback.id, 24));
    assert_ne!(false_callback.id, second_false_callback.id);
    let calls = generator.calls();
    assert_eq!(calls.len(), 5);
    assert!(calls.iter().all(|call| call.model == "user"));
    assert!(
        calls
            .iter()
            .all(|call| call.size == DatabaseIdGenerationSize::Undefined)
    );
}

#[test]
fn legacy_context_callback_precedes_the_database_callback() {
    let legacy = Arc::new(SequenceGenerator::new([DatabaseIdGenerationResult::Id(
        "legacy::user::?/+".into(),
    )]));
    let database = Arc::new(SequenceGenerator::new([DatabaseIdGenerationResult::Id(
        "database::must-not-run".into(),
    )]));
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.legacy_id_generator = Some(legacy.clone());
    config.database_id_generation = DatabaseIdGeneration::Callback(database.clone());
    config.add_plugin(TestUtilsPlugin::default()).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);

    let user = service
        .test()
        .unwrap()
        .create_user(TestUserOverrides::default());
    assert_eq!(user.id, "legacy::user::?/+");
    assert_eq!(
        legacy.calls(),
        [CallbackCall {
            model: "user".into(),
            size: DatabaseIdGenerationSize::Undefined,
            id: Some("legacy::user::?/+".into()),
        }]
    );
    assert!(database.calls().is_empty());
}

#[tokio::test]
async fn save_user_force_allows_factory_and_hook_ids_without_an_adapter_callback() {
    let generator = Arc::new(SequenceGenerator::new([DatabaseIdGenerationResult::Id(
        "factory::user::?/+".into(),
    )]));
    let hook = Arc::new(TestCreateHook::default());
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.database_id_generation = DatabaseIdGeneration::Callback(generator.clone());
    config.database_hooks = Some(hook.clone());
    config.add_plugin(TestUtilsPlugin::default()).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    let helpers = service.test().unwrap();

    let saved = helpers
        .save_user(helpers.create_user(TestUserOverrides::default()))
        .await
        .unwrap();

    assert_eq!(saved.id, "hook::forced-user::?/+");
    assert_eq!(
        *hook.seen.lock().unwrap(),
        [(
            DatabaseIdInput::String("factory::user::?/+".into()),
            Some("test"),
        )]
    );
    assert_eq!(generator.calls().len(), 1);
    assert_eq!(
        generator.calls()[0].size,
        DatabaseIdGenerationSize::Undefined
    );
}

#[tokio::test]
async fn falsey_factory_id_defers_without_reinvoking_the_callback() {
    let generator = Arc::new(SequenceGenerator::new([DatabaseIdGenerationResult::Id(
        String::new(),
    )]));
    let service = service(generator.clone());
    let helpers = service.test().unwrap();
    let draft = helpers.create_user(TestUserOverrides::default());
    assert!(draft.id.is_empty());

    let error = helpers.save_user(draft).await.unwrap_err();

    assert!(error.to_string().contains("did not return an id"));
    assert_eq!(generator.calls().len(), 1);
    assert_eq!(
        generator.calls()[0].size,
        DatabaseIdGenerationSize::Undefined
    );
}

#[tokio::test]
async fn forced_factory_ids_follow_database_serial_and_uuid_strategies() {
    for strategy in [
        DatabaseIdGeneration::Database,
        DatabaseIdGeneration::Serial,
        DatabaseIdGeneration::Uuid,
    ] {
        let mut config = AuthConfig::new(SECRET).unwrap();
        config.database_id_generation = strategy.clone();
        config.add_plugin(TestUtilsPlugin::default()).unwrap();
        let service = AuthService::new(Arc::new(MemoryStore::default()), config);
        let helpers = service.test().unwrap();
        let draft = helpers.create_user(TestUserOverrides::default());
        let draft_id = draft.id.clone();
        let saved = helpers.save_user(draft).await.unwrap();

        match strategy {
            DatabaseIdGeneration::Database => assert_eq!(saved.id, draft_id),
            DatabaseIdGeneration::Serial => assert_eq!(saved.id, "1"),
            DatabaseIdGeneration::Uuid => {
                assert_eq!(saved.id, draft_id);
                uuid::Uuid::parse_str(&saved.id).unwrap();
            }
            _ => unreachable!("the test has a closed strategy set"),
        }
    }
}

#[tokio::test]
async fn opaque_user_and_session_ids_flow_through_every_core_helper() {
    let generator = Arc::new(SequenceGenerator::new([
        DatabaseIdGenerationResult::Id("opaque::factory-user::?/+".into()),
        DatabaseIdGenerationResult::Id("opaque::login-session::?/+".into()),
        DatabaseIdGenerationResult::Id("opaque::headers-session::?/+".into()),
        DatabaseIdGenerationResult::Id("opaque::cookies-session::?/+".into()),
    ]));
    let service = service(generator.clone());
    let helpers = service.test().unwrap();
    let draft = helpers.create_user(TestUserOverrides::default());
    assert_eq!(draft.id, "opaque::factory-user::?/+");

    let saved = helpers.save_user(draft).await.unwrap();
    assert_eq!(saved.id, "opaque::factory-user::?/+");
    let login = helpers.login(&saved.id).await.unwrap();
    assert_eq!(login.user.id, saved.id);
    assert_eq!(login.session.id, "opaque::login-session::?/+");
    assert!(helpers.get_auth_headers(&saved.id).await.is_ok());
    assert!(helpers.get_cookies(&saved.id, None).await.is_ok());

    let calls = generator.calls();
    assert_eq!(
        calls
            .iter()
            .map(|call| (call.model.as_str(), call.size))
            .collect::<Vec<_>>(),
        [
            ("user", DatabaseIdGenerationSize::Undefined),
            ("session", DatabaseIdGenerationSize::Omitted),
            ("session", DatabaseIdGenerationSize::Omitted),
            ("session", DatabaseIdGenerationSize::Omitted),
        ]
    );
    helpers.delete_user(&saved.id).await.unwrap();
    let missing = helpers.login(&saved.id).await.unwrap_err();
    assert_eq!(missing.to_string(), format!("User not found: {}", saved.id));
}

fn service(generator: Arc<SequenceGenerator>) -> AuthService {
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.database_id_generation = DatabaseIdGeneration::Callback(generator);
    config.add_plugin(TestUtilsPlugin::default()).unwrap();
    AuthService::new(Arc::new(MemoryStore::default()), config)
}

fn is_base62(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
