use super::{CoreRoundTrip, StrategyDatabase};
use chrono::{Duration, Utc};
use lucid_auth::{
    DatabaseCreate, DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult,
    DatabaseIdGenerator, DatabaseIdInput, DatabaseIdPlan, DeviceAuthorizationStore, DeviceCode,
    DeviceCodeCreateOutcome, DeviceCodeStatus, postgres::PostgresDeviceAuthorizationStore,
};
use std::sync::Arc;

pub(super) async fn create(
    database: &StrategyDatabase,
    label: &str,
    user_id: &str,
    strategy: &DatabaseIdGeneration,
) -> Result<DeviceCode, Box<dyn std::error::Error>> {
    let store = PostgresDeviceAuthorizationStore::new((*database.store).clone());
    let create = DatabaseCreate::new(
        DeviceCode {
            id: String::new(),
            device_code: format!("strategy-{label}-device"),
            user_code: format!("STRATEGY-{label}"),
            user_id: Some(user_id.into()),
            expires_at: Utc::now() + Duration::minutes(10),
            status: DeviceCodeStatus::Pending,
            last_polled_at: None,
            polling_interval: Some(5_000.0),
            client_id: Some(format!("strategy-{label}-client")),
            scope: Some("openid profile".into()),
            resources: None,
            oauth_client_id: None,
        },
        DatabaseIdPlan::new(
            strategy.clone(),
            "deviceCode",
            DatabaseIdInput::Absent,
            false,
        ),
    );
    match store
        .create_device_code(create, database.store.as_ref())
        .await?
    {
        DeviceCodeCreateOutcome::Created(code) => Ok(code),
        DeviceCodeCreateOutcome::UniqueConflict => {
            Err("unexpected strategy device-code conflict".into())
        }
    }
}

pub(super) async fn assert_round_trip(
    database: &StrategyDatabase,
    ids: &CoreRoundTrip,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = PostgresDeviceAuthorizationStore::new((*database.store).clone());
    let device_code = store
        .find_device_code(&ids.device_code)
        .await?
        .expect("strategy device code");
    assert_eq!(device_code.id, ids.device_code_id);
    assert_eq!(device_code.user_id.as_deref(), Some(ids.user_id.as_str()));
    Ok(())
}

pub(super) async fn assert_physical_types(
    database: &StrategyDatabase,
    device_code_id: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let types = sqlx::query_as::<_, (String, String)>(
        r#"SELECT pg_typeof(id)::text, pg_typeof("userId")::text
             FROM "deviceCode" WHERE id::text = $1"#,
    )
    .bind(device_code_id)
    .fetch_one(&database.pool)
    .await?;
    assert_eq!(types, (expected.into(), "text".into()));
    Ok(())
}

pub(super) async fn assert_crud(
    database: &StrategyDatabase,
    ids: &CoreRoundTrip,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = PostgresDeviceAuthorizationStore::new((*database.store).clone());
    let duplicate = duplicate_record(ids);
    assert_eq!(
        store
            .create_device_code(duplicate, database.store.as_ref())
            .await?,
        DeviceCodeCreateOutcome::UniqueConflict
    );
    let updated = store
        .update_device_code_status(&ids.device_code_id, DeviceCodeStatus::Approved)
        .await?
        .expect("strategy device code update");
    assert_eq!(updated.status, DeviceCodeStatus::Approved);
    assert_eq!(
        store.delete_device_code(&ids.device_code_id).await?,
        Some(updated)
    );
    assert!(store.find_device_code(&ids.device_code).await?.is_none());
    Ok(())
}

fn duplicate_record(ids: &CoreRoundTrip) -> DatabaseCreate<DeviceCode> {
    DatabaseCreate::new(
        DeviceCode {
            id: String::new(),
            device_code: ids.device_code.clone(),
            user_code: "UNIQUE-DUPLICATE-CODE".into(),
            user_id: Some(ids.user_id.clone()),
            expires_at: Utc::now() + Duration::minutes(10),
            status: DeviceCodeStatus::Pending,
            last_polled_at: None,
            polling_interval: None,
            client_id: Some("duplicate-client".into()),
            scope: None,
            resources: None,
            oauth_client_id: None,
        },
        DatabaseIdPlan::new(
            DatabaseIdGeneration::Callback(Arc::new(UnexpectedDeviceId)),
            "deviceCode",
            DatabaseIdInput::Absent,
            false,
        ),
    )
}

#[derive(Debug)]
struct UnexpectedDeviceId;

impl DatabaseIdGenerator for UnexpectedDeviceId {
    fn generate(&self, _: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        panic!("a duplicate device code must not prepare an ID")
    }
}
