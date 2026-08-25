use super::support::*;

#[tokio::test]
async fn polling_reports_pending_denied_and_expired_in_the_pinned_order() {
    let fixture = fixture().await;
    insert(
        fixture.devices.as_ref(),
        record(
            "pending-device",
            "PENDING1",
            None,
            DeviceCodeStatus::Pending,
        ),
    )
    .await;
    let (status, headers, pending) = token(&fixture.app, "pending-device").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(pending["error"], "authorization_pending");

    insert(
        fixture.devices.as_ref(),
        record(
            "denied-device",
            "DENIED01",
            Some(fixture.user_id),
            DeviceCodeStatus::Denied,
        ),
    )
    .await;
    let (status, _, denied) = token(&fixture.app, "denied-device").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(denied["error"], "access_denied");
    assert!(
        fixture
            .devices
            .find_device_code("denied-device")
            .await
            .unwrap()
            .is_none()
    );

    let mut expired = record(
        "expired-device",
        "EXPIRED1",
        Some(fixture.user_id),
        DeviceCodeStatus::Approved,
    );
    expired.expires_at = Utc::now() - Duration::seconds(1);
    insert(fixture.devices.as_ref(), expired).await;
    let (status, _, expired) = token(&fixture.app, "expired-device").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(expired["error"], "expired_token");
    assert!(
        fixture
            .devices
            .find_device_code("expired-device")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn standalone_token_rejects_oauth_owned_codes_before_status_processing() {
    let fixture = fixture().await;
    let mut oauth = record(
        "oauth-device",
        "OAUTH001",
        Some(fixture.user_id),
        DeviceCodeStatus::Approved,
    );
    oauth.oauth_client_id = Some("oauth-client".into());
    insert(fixture.devices.as_ref(), oauth).await;
    let (status, _, body) = token(&fixture.app, "oauth-device").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"],
        "This device code must be exchanged at the OAuth token endpoint (/oauth2/token)."
    );
}

#[tokio::test]
async fn slow_down_precedes_expiration_and_does_not_delete_the_record() {
    let fixture = fixture().await;
    let mut record = record(
        "slow-device",
        "SLOW0001",
        Some(fixture.user_id),
        DeviceCodeStatus::Approved,
    );
    record.expires_at = Utc::now() - Duration::seconds(1);
    record.last_polled_at = Some(Utc::now());
    record.polling_interval = Some(5_000.0);
    insert(fixture.devices.as_ref(), record).await;

    let (status, _, body) = token(&fixture.app, "slow-device").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "slow_down");
    assert_eq!(body["error_description"], "Polling too frequently");
    let stored = fixture
        .devices
        .find_device_code("slow-device")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.polling_interval, Some(5_000.0));
}

#[tokio::test]
async fn client_ownership_is_checked_before_polling_state() {
    let fixture = fixture().await;
    let mut record = record("owned-device", "OWNED001", None, DeviceCodeStatus::Pending);
    record.last_polled_at = Some(Utc::now());
    record.polling_interval = Some(5_000.0);
    insert(fixture.devices.as_ref(), record).await;
    let (status, _, body) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/token",
        json!({
            "grant_type":GRANT,
            "device_code":"owned-device",
            "client_id":"wrong-client"
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "Client ID mismatch");
}
