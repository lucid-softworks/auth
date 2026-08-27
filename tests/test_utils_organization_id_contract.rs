#![cfg(feature = "axum")]

use lucid_auth::{
    AuthConfig, AuthService, DatabaseIdGeneration, DatabaseIdGenerationRequest,
    DatabaseIdGenerationResult, DatabaseIdGenerationSize, DatabaseIdGenerator,
    MemoryOrganizationStore, MemoryStore, OrganizationPlugin, TestOrganizationOverrides,
    TestUtilsPlugin,
};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct ContextIds {
    mode: CallbackMode,
    requests: Mutex<Vec<(String, DatabaseIdGenerationSize)>>,
}

#[derive(Debug, Clone, Copy)]
enum CallbackMode {
    Named,
    Empty,
    Defer,
}

impl DatabaseIdGenerator for ContextIds {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        self.requests
            .lock()
            .unwrap()
            .push((request.model.into(), request.size));
        match self.mode {
            CallbackMode::Named => {
                DatabaseIdGenerationResult::Id(format!("callback-{}", request.model))
            }
            CallbackMode::Empty => DatabaseIdGenerationResult::Id(String::new()),
            CallbackMode::Defer => DatabaseIdGenerationResult::Defer,
        }
    }
}

#[tokio::test]
async fn organization_context_ids_match_test_utils_callback_and_defer_rules() {
    for mode in [
        CallbackMode::Named,
        CallbackMode::Empty,
        CallbackMode::Defer,
    ] {
        assert_context_ids(mode).await;
    }
}

async fn assert_context_ids(mode: CallbackMode) {
    let callback = Arc::new(ContextIds {
        mode,
        requests: Mutex::new(Vec::new()),
    });
    let organizations = Arc::new(MemoryOrganizationStore::default());
    let mut config = AuthConfig::new([17_u8; 32]).unwrap();
    config.database_id_generation = DatabaseIdGeneration::Callback(callback.clone());
    config
        .add_plugin(OrganizationPlugin::new(organizations))
        .unwrap();
    config.add_plugin(TestUtilsPlugin::default()).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    let helpers = service.test().unwrap().organization().unwrap();

    let generated = helpers.create_organization(TestOrganizationOverrides::default());
    let overridden = helpers.create_organization(TestOrganizationOverrides {
        id: Some(String::new()),
        ..TestOrganizationOverrides::default()
    });
    assert_eq!(overridden.id, "");
    match mode {
        CallbackMode::Named => assert_eq!(generated.id, "callback-organization"),
        CallbackMode::Empty => assert_eq!(generated.id, ""),
        CallbackMode::Defer => assert!(is_base62(&generated.id, 24)),
    }
    if matches!(mode, CallbackMode::Empty) {
        let organization_error = helpers
            .save_organization(generated.clone())
            .await
            .unwrap_err();
        assert!(
            organization_error
                .to_string()
                .contains("did not return an id")
        );
        let member_error = helpers
            .add_member("context-member", "missing-organization", None)
            .await
            .unwrap_err();
        assert!(member_error.to_string().contains("did not return an id"));
    } else {
        helpers.save_organization(generated.clone()).await.unwrap();
        let member = helpers
            .add_member("context-member", &generated.id, None)
            .await
            .unwrap();
        match mode {
            CallbackMode::Named => assert_eq!(member.id, "callback-member"),
            CallbackMode::Defer => assert!(is_base62(&member.id, 24)),
            CallbackMode::Empty => unreachable!("the empty mode returns above"),
        }
    }
    assert_eq!(
        *callback.requests.lock().unwrap(),
        vec![
            ("organization".into(), DatabaseIdGenerationSize::Undefined),
            ("organization".into(), DatabaseIdGenerationSize::Undefined),
            ("member".into(), DatabaseIdGenerationSize::Undefined),
        ]
    );
}

#[tokio::test]
async fn deferred_organization_and_member_fallback_ids_are_random() {
    let callback = Arc::new(ContextIds {
        mode: CallbackMode::Defer,
        requests: Mutex::new(Vec::new()),
    });
    let organizations = Arc::new(MemoryOrganizationStore::default());
    let mut config = AuthConfig::new([20_u8; 32]).unwrap();
    config.database_id_generation = DatabaseIdGeneration::Callback(callback.clone());
    config
        .add_plugin(OrganizationPlugin::new(organizations))
        .unwrap();
    config.add_plugin(TestUtilsPlugin::default()).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    let helpers = service.test().unwrap().organization().unwrap();

    let first = helpers.create_organization(TestOrganizationOverrides::default());
    let second = helpers.create_organization(TestOrganizationOverrides::default());
    assert!(is_base62(&first.id, 24));
    assert!(is_base62(&second.id, 24));
    assert_ne!(first.id, second.id);
    helpers.save_organization(first.clone()).await.unwrap();
    helpers.save_organization(second).await.unwrap();

    let first_member = helpers
        .add_member("deferred-member-one", &first.id, None)
        .await
        .unwrap();
    let second_member = helpers
        .add_member("deferred-member-two", &first.id, None)
        .await
        .unwrap();
    assert!(is_base62(&first_member.id, 24));
    assert!(is_base62(&second_member.id, 24));
    assert_ne!(first_member.id, second_member.id);
    assert_eq!(
        *callback.requests.lock().unwrap(),
        [
            ("organization".into(), DatabaseIdGenerationSize::Undefined),
            ("organization".into(), DatabaseIdGenerationSize::Undefined),
            ("member".into(), DatabaseIdGenerationSize::Undefined),
            ("member".into(), DatabaseIdGenerationSize::Undefined),
        ]
    );
}

#[tokio::test]
async fn organization_and_member_force_allow_ids_follow_serial_and_uuid_rules() {
    let organizations = Arc::new(MemoryOrganizationStore::default());
    let mut serial = AuthConfig::new([18_u8; 32]).unwrap();
    serial.database_id_generation = DatabaseIdGeneration::Serial;
    serial
        .add_plugin(OrganizationPlugin::new(organizations))
        .unwrap();
    serial.add_plugin(TestUtilsPlugin::default()).unwrap();
    let serial = AuthService::new(Arc::new(MemoryStore::default()), serial);
    let serial = serial.test().unwrap().organization().unwrap();
    let generated = serial.create_organization(TestOrganizationOverrides::default());
    assert!(is_base62(&generated.id, 24));
    let stored = serial.save_organization(generated).await.unwrap();
    assert_eq!(stored.id, "1");
    let member = serial
        .add_member("serial-user", &stored.id, None)
        .await
        .unwrap();
    assert_eq!(member.id, "1");
    let explicit = serial.create_organization(TestOrganizationOverrides {
        id: Some("42".into()),
        slug: Some("serial-explicit".into()),
        ..TestOrganizationOverrides::default()
    });
    assert_eq!(serial.save_organization(explicit).await.unwrap().id, "42");

    let organizations = Arc::new(MemoryOrganizationStore::default());
    let mut uuid = AuthConfig::new([19_u8; 32]).unwrap();
    uuid.database_id_generation = DatabaseIdGeneration::Uuid;
    uuid.add_plugin(OrganizationPlugin::new(organizations))
        .unwrap();
    uuid.add_plugin(TestUtilsPlugin::default()).unwrap();
    let uuid = AuthService::new(Arc::new(MemoryStore::default()), uuid);
    let uuid = uuid.test().unwrap().organization().unwrap();
    let generated = uuid.create_organization(TestOrganizationOverrides::default());
    let expected = generated.id.clone();
    let stored = uuid.save_organization(generated).await.unwrap();
    assert_eq!(stored.id, expected);
    uuid::Uuid::parse_str(&stored.id).unwrap();
    let invalid = uuid.create_organization(TestOrganizationOverrides {
        id: Some("not-a-uuid".into()),
        slug: Some("uuid-invalid".into()),
        ..TestOrganizationOverrides::default()
    });
    let error = uuid.save_organization(invalid).await.unwrap_err();
    assert!(error.to_string().contains("did not return an id"));
}

fn is_base62(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
