use super::{Sender, TemporaryEmail, verify_input};
use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, BeforeDatabaseCreateHook, DatabaseCreateRecord,
    DatabaseHookContext, DatabaseHooks, DatabaseIdInput, DatabaseModel, DatabaseRecord,
    MemoryStore, PhoneNumberConfig, PhoneNumberPlugin, PhoneNumberRequestContext,
    PhoneNumberSignUpConfig, PhoneNumberStore,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct CreateHookAudit {
    events: Mutex<Vec<String>>,
}

#[async_trait]
impl DatabaseHooks for CreateHookAudit {
    async fn before_create(
        &self,
        record: &DatabaseCreateRecord,
        _context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseCreateHook, AuthError> {
        if record.model() == DatabaseModel::User {
            assert_eq!(record.id(), &DatabaseIdInput::Absent);
            self.events.lock().await.push("before:user:absent".into());
        }
        Ok(BeforeDatabaseCreateHook::Continue)
    }

    async fn after_create(
        &self,
        record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if let DatabaseRecord::User(user) = record {
            assert!(!user.id.is_empty());
            self.events
                .lock()
                .await
                .push(format!("after:user:{}", user.id));
        }
        Ok(())
    }
}

#[tokio::test]
async fn sign_up_on_verification_runs_create_hooks_around_the_persisted_id() {
    let store = Arc::new(MemoryStore::default());
    let sender = Arc::new(Sender::default());
    let hooks = Arc::new(CreateHookAudit::default());
    let mut config = AuthConfig::new([39_u8; 32]).unwrap();
    config.database_hooks = Some(hooks.clone());
    config
        .add_plugin(PhoneNumberPlugin::new(
            store.clone(),
            PhoneNumberConfig {
                send_otp: Some(sender.clone()),
                sign_up_on_verification: Some(PhoneNumberSignUpConfig {
                    temporary_email: Arc::new(TemporaryEmail),
                    temporary_name: None,
                }),
                ..PhoneNumberConfig::default()
            },
        ))
        .unwrap();
    let service = AuthService::try_new(store.clone(), config).unwrap();
    let phone_number = "hooked-phone-create";
    service
        .send_phone_number_otp(phone_number, PhoneNumberRequestContext::default())
        .await
        .unwrap();
    let code = sender.messages.lock().await.last().unwrap().code.clone();
    let mut input = verify_input(phone_number, &code);
    input.disable_session = true;
    let verified = service.verify_phone_number(None, input).await.unwrap();

    assert_eq!(
        *hooks.events.lock().await,
        vec![
            "before:user:absent".to_owned(),
            format!("after:user:{}", verified.user.id),
        ]
    );
    assert_eq!(
        store
            .find_user_by_phone_number(phone_number)
            .await
            .unwrap()
            .unwrap()
            .id,
        verified.user.id
    );
}
