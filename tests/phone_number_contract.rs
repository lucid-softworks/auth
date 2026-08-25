use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, DatabaseModel, EmailSignUpInput, MemoryStore,
    PhoneNumberConfig, PhoneNumberError, PhoneNumberMessage, PhoneNumberOtpSender,
    PhoneNumberOtpVerifier, PhoneNumberPlugin, PhoneNumberRequestContext, PhoneNumberSignInInput,
    PhoneNumberSignUpConfig, PhoneNumberTemporaryEmail, PhoneNumberVerificationCallback,
    PhoneNumberVerified, PhoneNumberVerifyInput,
};
use serde_json::{Map, json};
use std::sync::Arc;
use tokio::sync::Mutex;

#[path = "phone_number_contract/attempts.rs"]
mod attempts;
#[path = "phone_number_contract/hibp_order.rs"]
mod hibp_order;

#[derive(Default)]
struct Sender {
    messages: Mutex<Vec<PhoneNumberMessage>>,
}

#[async_trait]
impl PhoneNumberOtpSender for Sender {
    async fn send(
        &self,
        message: PhoneNumberMessage,
        _context: PhoneNumberRequestContext,
    ) -> Result<(), AuthError> {
        self.messages.lock().await.push(message);
        Ok(())
    }
}

struct TemporaryEmail;

#[derive(Default)]
struct ExternalVerifier {
    contexts: Mutex<Vec<PhoneNumberRequestContext>>,
}

#[async_trait]
impl PhoneNumberOtpVerifier for ExternalVerifier {
    async fn verify(
        &self,
        _phone_number: &str,
        code: &str,
        context: PhoneNumberRequestContext,
    ) -> Result<bool, AuthError> {
        self.contexts.lock().await.push(context);
        Ok(code == "provider-code")
    }
}

#[derive(Default)]
struct VerificationCallback {
    calls: Mutex<Vec<(PhoneNumberVerified, PhoneNumberRequestContext)>>,
}

#[async_trait]
impl PhoneNumberVerificationCallback for VerificationCallback {
    async fn call(
        &self,
        verified: PhoneNumberVerified,
        context: PhoneNumberRequestContext,
    ) -> Result<(), AuthError> {
        self.calls.lock().await.push((verified, context));
        Ok(())
    }
}

#[async_trait]
impl PhoneNumberTemporaryEmail for TemporaryEmail {
    async fn generate(&self, phone_number: &str) -> Result<String, AuthError> {
        Ok(format!("{phone_number}@phone.test"))
    }
}

fn fixture() -> (AuthService, Arc<Sender>, Arc<Sender>) {
    configured_fixture(false)
}

fn configured_fixture(require_verification: bool) -> (AuthService, Arc<Sender>, Arc<Sender>) {
    let store = Arc::new(MemoryStore::default());
    let otp = Arc::new(Sender::default());
    let reset = Arc::new(Sender::default());
    let mut config = AuthConfig::new([31_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config
        .add_plugin(PhoneNumberPlugin::new(
            store.clone(),
            PhoneNumberConfig {
                send_otp: Some(otp.clone()),
                send_password_reset_otp: Some(reset.clone()),
                sign_up_on_verification: Some(PhoneNumberSignUpConfig {
                    temporary_email: Arc::new(TemporaryEmail),
                    temporary_name: None,
                }),
                require_verification,
                ..PhoneNumberConfig::default()
            },
        ))
        .unwrap();
    (AuthService::try_new(store, config).unwrap(), otp, reset)
}

#[tokio::test]
async fn required_verification_precedes_password_checks_and_uses_signup_fields() {
    let (service, otp, _) = configured_fixture(true);
    let phone_number = "signup-phone-field";
    service
        .sign_up_email(
            EmailSignUpInput {
                name: "Phone field user".into(),
                email: "phone-field-user@example.com".into(),
                password: "correct horse battery staple".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                username: None,
                display_username: None,
                additional_fields: Map::from_iter([("phoneNumber".into(), json!(phone_number))]),
            },
            None,
            None,
        )
        .await
        .unwrap();
    let result = service
        .sign_in_phone_number(PhoneNumberSignInInput {
            phone_number: phone_number.into(),
            password: "deliberately wrong".into(),
            remember_me: None,
            origin: None,
            ip_address: None,
            user_agent: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(AuthError::PhoneNumber(
            PhoneNumberError::PhoneNumberNotVerified
        ))
    ));
    let code = otp.messages.lock().await.last().unwrap().code.clone();
    let verified = service
        .verify_phone_number(None, verify_input(phone_number, &code))
        .await
        .unwrap();
    assert_eq!(verified.user.email, "phone-field-user@example.com");
    assert_eq!(
        verified.user.additional_fields.get("phoneNumberVerified"),
        Some(&json!(true))
    );
}

#[tokio::test]
async fn custom_verification_and_callback_receive_narrowed_request_context() {
    let store = Arc::new(MemoryStore::default());
    let sender = Arc::new(Sender::default());
    let verifier = Arc::new(ExternalVerifier::default());
    let callback = Arc::new(VerificationCallback::default());
    let mut config = AuthConfig::new([32_u8; 32]).unwrap();
    config
        .add_plugin(PhoneNumberPlugin::new(
            store.clone(),
            PhoneNumberConfig {
                send_otp: Some(sender),
                verify_otp: Some(verifier.clone()),
                callback_on_verification: Some(callback.clone()),
                sign_up_on_verification: Some(PhoneNumberSignUpConfig {
                    temporary_email: Arc::new(TemporaryEmail),
                    temporary_name: None,
                }),
                ..PhoneNumberConfig::default()
            },
        ))
        .unwrap();
    let service = AuthService::try_new(store, config).unwrap();
    let mut input = verify_input("external-verifier", "wrong");
    input.origin = Some("https://app.example.com".into());
    input.ip_address = Some("192.0.2.1".into());
    assert!(matches!(
        service.verify_phone_number(None, input.clone()).await,
        Err(AuthError::PhoneNumber(PhoneNumberError::InvalidOtp))
    ));
    input.code = "provider-code".into();
    let verified = service.verify_phone_number(None, input).await.unwrap();
    assert_eq!(verified.user.name, "external-verifier");
    let contexts = verifier.contexts.lock().await;
    assert_eq!(contexts.len(), 2);
    assert_eq!(
        contexts[1].origin.as_deref(),
        Some("https://app.example.com")
    );
    drop(contexts);
    let calls = callback.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0.user.id, verified.user.id);
    assert_eq!(calls[0].1.ip_address.as_deref(), Some("192.0.2.1"));
}

#[tokio::test]
async fn expired_otp_is_deleted_and_then_reported_missing() {
    let store = Arc::new(MemoryStore::default());
    let sender = Arc::new(Sender::default());
    let mut config = AuthConfig::new([33_u8; 32]).unwrap();
    config
        .add_plugin(PhoneNumberPlugin::new(
            store.clone(),
            PhoneNumberConfig {
                send_otp: Some(sender.clone()),
                expires_in: chrono::Duration::zero(),
                ..PhoneNumberConfig::default()
            },
        ))
        .unwrap();
    let service = AuthService::try_new(store, config).unwrap();
    service
        .send_phone_number_otp("expired-phone", PhoneNumberRequestContext::default())
        .await
        .unwrap();
    let code = sender.messages.lock().await.last().unwrap().code.clone();
    assert!(matches!(
        service
            .consume_phone_number_otp("expired-phone", &code)
            .await,
        Err(AuthError::PhoneNumber(PhoneNumberError::OtpExpired))
    ));
    assert!(matches!(
        service
            .consume_phone_number_otp("expired-phone", &code)
            .await,
        Err(AuthError::PhoneNumber(PhoneNumberError::OtpNotFound))
    ));
}

fn verify_input(phone_number: &str, code: &str) -> PhoneNumberVerifyInput {
    PhoneNumberVerifyInput {
        phone_number: phone_number.into(),
        code: code.into(),
        disable_session: false,
        update_phone_number: false,
        additional_fields: Map::new(),
        origin: None,
        ip_address: None,
        user_agent: None,
    }
}

#[test]
fn descriptor_schema_migration_and_defaults_match_better_auth_1_7_1() {
    let (service, _, _) = fixture();
    let descriptor = service
        .plugin_metadata()
        .iter()
        .find(|descriptor| descriptor.id == "phone-number")
        .unwrap();
    assert_eq!(descriptor.client.unwrap().factory, "phoneNumberClient");
    assert_eq!(descriptor.endpoints.len(), 5);
    assert_eq!(descriptor.rate_limits.len(), 4);
    assert!(
        descriptor
            .rate_limits
            .iter()
            .all(|limit| limit.window == 60 && limit.max == 10)
    );
    let fields = service.database_schema_fields(DatabaseModel::User);
    let phone_number = &fields["phoneNumber"];
    assert!(!phone_number.required);
    assert!(phone_number.input && phone_number.returned);
    assert!(phone_number.unique && phone_number.sortable);
    let verified = &fields["phoneNumberVerified"];
    assert!(!verified.required);
    assert!(!verified.input && verified.returned);
    let migration = service
        .plugin_migrations()
        .into_iter()
        .find(|migration| migration.plugin_id == "phone-number")
        .unwrap();
    assert_eq!(migration.migration.id, "better-auth-phone-number-schema");

    let defaults = PhoneNumberConfig::default();
    assert_eq!(defaults.otp_length, 6);
    assert_eq!(defaults.expires_in, chrono::Duration::seconds(300));
    assert_eq!(defaults.allowed_attempts, 3);
    assert!(!defaults.require_verification);
}

#[tokio::test]
async fn opaque_phone_signup_reset_and_password_sign_in_match_better_auth() {
    let (service, otp, reset) = fixture();
    let phone_number = "opaque-phone-number";
    service
        .send_phone_number_otp(phone_number, PhoneNumberRequestContext::default())
        .await
        .unwrap();
    let code = otp.messages.lock().await.last().unwrap().code.clone();
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|byte| byte.is_ascii_digit()));

    let verified = service
        .verify_phone_number(None, verify_input(phone_number, &code))
        .await
        .unwrap();
    assert!(verified.token.is_some());
    assert_eq!(
        verified.user.additional_fields.get("phoneNumber"),
        Some(&json!(phone_number))
    );
    assert_eq!(
        verified.user.additional_fields.get("phoneNumberVerified"),
        Some(&json!(true))
    );
    assert!(matches!(
        service
            .verify_phone_number(None, verify_input(phone_number, &code))
            .await,
        Err(AuthError::PhoneNumber(PhoneNumberError::OtpNotFound))
    ));

    service
        .request_phone_number_password_reset(phone_number, PhoneNumberRequestContext::default())
        .await
        .unwrap();
    let reset_code = reset.messages.lock().await.last().unwrap().code.clone();
    service
        .reset_phone_number_password(
            phone_number,
            &reset_code,
            "correct horse battery staple".into(),
        )
        .await
        .unwrap();
    let signed_in = service
        .sign_in_phone_number(PhoneNumberSignInInput {
            phone_number: phone_number.into(),
            password: "correct horse battery staple".into(),
            remember_me: Some(false),
            origin: None,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();
    assert_eq!(signed_in.session.user.id, verified.user.id);
}

#[tokio::test]
async fn authenticated_phone_replacement_consumes_otp_and_enforces_uniqueness() {
    let (service, otp, _) = fixture();
    service
        .send_phone_number_otp("phone-owner", PhoneNumberRequestContext::default())
        .await
        .unwrap();
    let owner_code = otp.messages.lock().await.last().unwrap().code.clone();
    let owner = service
        .verify_phone_number(None, verify_input("phone-owner", &owner_code))
        .await
        .unwrap();
    let owner_token = owner.token.clone().unwrap();
    let session = service.session(&owner_token).await.unwrap().unwrap();

    service
        .send_phone_number_otp("occupied-phone", PhoneNumberRequestContext::default())
        .await
        .unwrap();
    let occupied_code = otp.messages.lock().await.last().unwrap().code.clone();
    service
        .verify_phone_number(None, verify_input("occupied-phone", &occupied_code))
        .await
        .unwrap();
    service
        .send_phone_number_otp("occupied-phone", PhoneNumberRequestContext::default())
        .await
        .unwrap();
    let collision_code = otp.messages.lock().await.last().unwrap().code.clone();
    let mut collision = verify_input("occupied-phone", &collision_code);
    collision.update_phone_number = true;
    assert!(matches!(
        service.verify_phone_number(Some(&session), collision).await,
        Err(AuthError::PhoneNumber(PhoneNumberError::PhoneNumberExists))
    ));

    service
        .send_phone_number_otp("replacement-phone", PhoneNumberRequestContext::default())
        .await
        .unwrap();
    let replacement_code = otp.messages.lock().await.last().unwrap().code.clone();
    let mut replacement = verify_input("replacement-phone", &replacement_code);
    replacement.update_phone_number = true;
    replacement.disable_session = true;
    let updated = service
        .verify_phone_number(Some(&session), replacement)
        .await
        .unwrap();
    assert_eq!(updated.user.id, owner.user.id);
    assert_eq!(updated.token.as_deref(), Some(owner_token.as_str()));
    assert_eq!(
        updated.user.additional_fields.get("phoneNumber"),
        Some(&json!("replacement-phone"))
    );
}
