use super::*;

pub(super) async fn insert(
    store: &PostgresDeviceAuthorizationStore,
    code: DeviceCode,
) -> Result<DeviceCode, Box<dyn std::error::Error>> {
    match store.create_device_code(code).await? {
        DeviceCodeCreateOutcome::Created(code) => Ok(code),
        DeviceCodeCreateOutcome::UniqueConflict => Err("unexpected device-code conflict".into()),
    }
}
