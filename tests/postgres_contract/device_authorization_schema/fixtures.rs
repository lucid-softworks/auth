use super::*;

pub(super) async fn insert(
    store: &PostgresDeviceAuthorizationStore,
    auth_store: &PostgresStore,
    code: DeviceCode,
) -> Result<DeviceCode, Box<dyn std::error::Error>> {
    match store.create_device_code(create(code), auth_store).await? {
        DeviceCodeCreateOutcome::Created(code) => Ok(code),
        DeviceCodeCreateOutcome::UniqueConflict => Err("unexpected device-code conflict".into()),
    }
}
