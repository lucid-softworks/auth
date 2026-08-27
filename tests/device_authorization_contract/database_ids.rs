use super::support::*;
use async_trait::async_trait;
use lucid_auth::{
    DatabaseIdGenerationRequest, DatabaseIdGenerationResult, DatabaseIdGenerationSize,
    DatabaseIdGenerator, DeviceCodeGenerator,
};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy)]
enum CallbackResult {
    Fixed,
    Defer,
}

#[derive(Debug)]
struct IdLedger {
    calls: Mutex<Vec<(String, DatabaseIdGenerationSize)>>,
    result: CallbackResult,
}

impl IdLedger {
    fn new(result: CallbackResult) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            result,
        }
    }
}

impl DatabaseIdGenerator for IdLedger {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        self.calls
            .lock()
            .unwrap()
            .push((request.model.into(), request.size));
        match self.result {
            CallbackResult::Fixed => {
                DatabaseIdGenerationResult::Id("opaque::deviceCode::?/+".into())
            }
            CallbackResult::Defer => DatabaseIdGenerationResult::Defer,
        }
    }
}

struct FixedCode(&'static str);

#[async_trait]
impl DeviceCodeGenerator for FixedCode {
    async fn generate(&self) -> Result<String, lucid_auth::AuthError> {
        Ok(self.0.into())
    }
}

fn application(strategy: DatabaseIdGeneration) -> (Router, Arc<MemoryDeviceAuthorizationStore>) {
    let devices = Arc::new(MemoryDeviceAuthorizationStore::new());
    let mut device_config = DeviceAuthorizationConfig::default();
    device_config.generate_device_code = Some(Arc::new(FixedCode("fixed-device-token")));
    device_config.generate_user_code = Some(Arc::new(FixedCode("FIXEDUSR")));
    let mut config = AuthConfig::new([212_u8; 32]).unwrap();
    config.database_id_generation = strategy;
    config.set_base_url("http://localhost/api/auth").unwrap();
    config
        .add_plugin(DeviceAuthorizationPlugin::from_arc(
            device_config,
            devices.clone() as Arc<_>,
        ))
        .unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    (lucid_auth::axum::router(service), devices)
}

async fn issue_fixed(app: &Router) -> (StatusCode, Value) {
    let (status, _, body) = json_request(
        app,
        "POST",
        "/api/auth/device/code",
        json!({"client_id":"native-client"}),
        None,
    )
    .await;
    (status, body)
}

async fn generated_id(strategy: DatabaseIdGeneration) -> String {
    let (app, devices) = application(strategy);
    let (status, body) = issue_fixed(&app).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_code"], "fixed-device-token");
    assert_eq!(body["user_code"], "FIXEDUSR");
    devices
        .find_device_code("fixed-device-token")
        .await
        .unwrap()
        .unwrap()
        .id
}

async fn assert_deferred_rejected(strategy: DatabaseIdGeneration) {
    let (app, devices) = application(strategy);
    let (status, body) = issue_fixed(&app).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(
        devices
            .find_device_code("fixed-device-token")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn callback_is_canonical_opaque_and_lazy_after_token_conflicts() {
    let ledger = Arc::new(IdLedger::new(CallbackResult::Fixed));
    let (app, devices) = application(DatabaseIdGeneration::Callback(ledger.clone()));
    let (status, body) = issue_fixed(&app).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let stored = devices
        .find_device_code("fixed-device-token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.id, "opaque::deviceCode::?/+");
    assert_eq!(
        *ledger.calls.lock().unwrap(),
        [("deviceCode".into(), DatabaseIdGenerationSize::Omitted)]
    );

    let (status, _) = issue_fixed(&app).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(ledger.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn memory_honors_application_uuid_and_serial_strategies() {
    let default = generated_id(DatabaseIdGeneration::Default).await;
    assert_eq!(default.len(), 32);
    assert!(default.bytes().all(|byte| byte.is_ascii_alphanumeric()));

    let uuid = generated_id(DatabaseIdGeneration::Uuid).await;
    assert_eq!(uuid::Uuid::parse_str(&uuid).unwrap().to_string(), uuid);

    assert_eq!(generated_id(DatabaseIdGeneration::Serial).await, "1");
}

#[tokio::test]
async fn memory_rejects_every_ordinary_deferred_id() {
    assert_deferred_rejected(DatabaseIdGeneration::Database).await;
    let deferring = Arc::new(IdLedger::new(CallbackResult::Defer));
    assert_deferred_rejected(DatabaseIdGeneration::Callback(deferring.clone())).await;
    assert_eq!(
        *deferring.calls.lock().unwrap(),
        [("deviceCode".into(), DatabaseIdGenerationSize::Omitted)]
    );
}
