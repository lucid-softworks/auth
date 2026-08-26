use super::{oauth_support::*, support::*};

#[tokio::test]
async fn companion_plugin_advertises_and_executes_the_oauth_device_grant() {
    let fixture = oauth_fixture().await;
    assert_oauth_device_metadata(&fixture.app).await;
    let issued = oauth_issue(
        &fixture.app,
        json!({
            "client_id": CLIENT_ID,
            "scope": "  openid\tprofile  "
        }),
    )
    .await;
    let device_code = issued["device_code"].as_str().unwrap();
    let user_code = issued["user_code"].as_str().unwrap();
    assert_eq!(
        fixture
            .devices
            .find_device_code(device_code)
            .await
            .unwrap()
            .unwrap()
            .scope
            .as_deref(),
        Some("openid profile")
    );
    approve_device(&fixture, user_code).await;

    let (status, headers, tokens) = oauth_token(
        &fixture.app,
        &[("device_code", device_code), ("client_id", CLIENT_ID)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "openid profile");
    assert!(tokens["access_token"].is_string());
    assert!(
        fixture
            .devices
            .find_device_code(device_code)
            .await
            .unwrap()
            .is_none()
    );
}

async fn assert_oauth_device_metadata(app: &Router) {
    let (status, _, metadata) = json_request(
        app,
        "GET",
        "/api/auth/.well-known/oauth-authorization-server",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{metadata}");
    assert_eq!(
        metadata["device_authorization_endpoint"],
        "http://localhost/api/auth/device/code"
    );
    assert!(
        metadata["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!(GRANT))
    );
}

async fn approve_device(fixture: &OAuthFixture, user_code: &str) {
    let (status, _, verification) = json_request(
        &fixture.app,
        "GET",
        &format!("/api/auth/device?user_code={user_code}"),
        Value::Null,
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verification}");
    assert_eq!(verification["client_id"], CLIENT_ID);
    let (status, _, decision) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/approve",
        json!({"userCode":user_code}),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{decision}");
}

#[tokio::test]
async fn oauth_ownership_is_rejected_before_authentication_and_polling() {
    let fixture = oauth_fixture().await;
    let (status, _, invalid_client) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/code",
        json!({"client_id":"unregistered-client"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid_client}");
    assert_eq!(invalid_client["error"], "invalid_client");
    assert_eq!(invalid_client["error_description"], "Invalid client ID");

    let mut owned = oauth_record("owned-device", "OWNED001", None, DeviceCodeStatus::Pending);
    owned.last_polled_at = Some(Utc::now());
    owned.polling_interval = Some(5_000.0);
    let original_poll = owned.last_polled_at;
    insert(fixture.devices.as_ref(), owned).await;

    let (status, _, mismatch) = oauth_token(
        &fixture.app,
        &[
            ("device_code", "owned-device"),
            ("client_id", "unregistered-client"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{mismatch}");
    assert_eq!(mismatch["error"], "invalid_grant");
    assert_eq!(mismatch["error_description"], "Client ID mismatch");
    let stored = fixture
        .devices
        .find_device_code("owned-device")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.last_polled_at, original_poll);

    let mut standalone = oauth_record(
        "standalone-device",
        "STAND001",
        None,
        DeviceCodeStatus::Pending,
    );
    standalone.oauth_client_id = None;
    standalone.client_id = Some("native-client".into());
    insert(fixture.devices.as_ref(), standalone).await;
    let (status, _, invalid) = oauth_token(
        &fixture.app,
        &[
            ("device_code", "standalone-device"),
            ("client_id", "unregistered-client"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}");
    assert_eq!(invalid["error"], "invalid_grant");
    assert_eq!(invalid["error_description"], "invalid device code");
}

#[tokio::test]
async fn resource_subset_validation_happens_before_atomic_consumption() {
    let fixture = oauth_fixture().await;
    for resource in [json!([]), json!([42])] {
        let (status, _, invalid_resource) = json_request(
            &fixture.app,
            "POST",
            "/api/auth/device/code",
            json!({"client_id":CLIENT_ID,"resource":resource}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid_resource}");
        assert_eq!(invalid_resource["error"], "invalid_target");
        assert_eq!(
            invalid_resource["error_description"],
            "Invalid resource indicator"
        );
    }

    insert(
        fixture.devices.as_ref(),
        oauth_record(
            "resource-device",
            "RESOURC1",
            Some(fixture.user_id.clone()),
            DeviceCodeStatus::Approved,
        ),
    )
    .await;
    let (status, _, rejected) = oauth_token(
        &fixture.app,
        &[
            ("device_code", "resource-device"),
            ("client_id", CLIENT_ID),
            ("resource", "https://device.example/not-authorized"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert_eq!(rejected["error"], "invalid_target");
    assert_eq!(
        rejected["error_description"],
        "Requested resource was not authorized by the user"
    );
    assert!(
        fixture
            .devices
            .find_device_code("resource-device")
            .await
            .unwrap()
            .is_some()
    );

    let (status, _, tokens) = oauth_token(
        &fixture.app,
        &[
            ("device_code", "resource-device"),
            ("client_id", CLIENT_ID),
            ("resource", RESOURCE),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert!(
        fixture
            .devices
            .find_device_code("resource-device")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn missing_user_is_a_server_error_before_atomic_consumption() {
    let fixture = oauth_fixture().await;
    insert(
        fixture.devices.as_ref(),
        oauth_record(
            "missing-user-device",
            "NOUSER01",
            Some("missing-user".into()),
            DeviceCodeStatus::Approved,
        ),
    )
    .await;
    let (status, _, missing_user) = oauth_token(
        &fixture.app,
        &[
            ("device_code", "missing-user-device"),
            ("client_id", CLIENT_ID),
            ("resource", RESOURCE),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{missing_user}");
    assert_eq!(missing_user["error"], "server_error");
    assert_eq!(missing_user["error_description"], "User not found");
    assert!(
        fixture
            .devices
            .find_device_code("missing-user-device")
            .await
            .unwrap()
            .is_some()
    );
}
