use super::{fixtures::insert, *};

pub(super) async fn all_fields_and_unique_codes(
    store: &PostgresDeviceAuthorizationStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner = Uuid::new_v4();
    let mut expected = code("round-trip", Some(owner));
    expected.expires_at = postgres_timestamp(expected.expires_at);
    expected.last_polled_at = Some(postgres_timestamp(Utc::now()));
    expected.status = DeviceCodeStatus::Approved;
    let stored = insert(store, expected.clone()).await?;
    assert_eq!(stored, expected);
    assert_eq!(
        store.find_device_code(&expected.device_code).await?,
        Some(expected.clone())
    );
    assert_eq!(
        store
            .find_device_code_by_user_code(&expected.user_code)
            .await?,
        Some(expected.clone())
    );

    let mut duplicate_device = code("unique-device", None);
    duplicate_device.device_code = expected.device_code.clone();
    assert_eq!(
        store.create_device_code(duplicate_device).await?,
        DeviceCodeCreateOutcome::UniqueConflict
    );
    let mut duplicate_user = code("unique-user", None);
    duplicate_user.user_code = expected.user_code.clone();
    assert_eq!(
        store.create_device_code(duplicate_user).await?,
        DeviceCodeCreateOutcome::UniqueConflict
    );

    let polled_at = postgres_timestamp(Utc::now() + Duration::seconds(1));
    let polled = store
        .update_last_polled_at(expected.id, polled_at)
        .await?
        .expect("poll update");
    assert_eq!(polled.last_polled_at, Some(polled_at));
    let denied = store
        .update_device_code_status(expected.id, DeviceCodeStatus::Denied)
        .await?
        .expect("ordinary status update");
    assert_eq!(denied.status, DeviceCodeStatus::Denied);
    assert_eq!(store.delete_device_code(expected.id).await?, Some(denied));
    assert!(
        store
            .find_device_code(&expected.device_code)
            .await?
            .is_none()
    );
    Ok(())
}

fn postgres_timestamp(value: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
    chrono::DateTime::from_timestamp_micros(value.timestamp_micros())
        .expect("current timestamps are representable")
}
