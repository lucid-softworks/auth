use super::support::*;

#[tokio::test]
async fn standalone_flow_claims_approves_and_exchanges_without_setting_a_cookie() {
    let fixture = fixture().await;
    let issued = issue(&fixture.app).await;
    let device_code = issued["device_code"].as_str().unwrap();
    let user_code = issued["user_code"].as_str().unwrap();

    let (status, _, anonymous) = json_request(
        &fixture.app,
        "GET",
        &format!("/api/auth/device?user_code={user_code}"),
        Value::Null,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(anonymous, json!({"user_code":user_code,"status":"pending"}));

    let (status, _, owner) = json_request(
        &fixture.app,
        "GET",
        &format!("/api/auth/device?user_code={user_code}"),
        Value::Null,
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(owner["client_id"], "native-client");
    assert_eq!(owner["scope"], "openid profile");

    let (status, _, body) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/approve",
        json!({"userCode": user_code}),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"success":true}));

    let (status, headers, credential) = token(&fixture.app, device_code).await;
    assert_eq!(status, StatusCode::OK, "{credential}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert!(headers.get(header::SET_COOKIE).is_none());
    assert_eq!(credential["token_type"], "Bearer");
    assert_eq!(credential["scope"], "openid profile");
    let access_token = credential["access_token"].as_str().unwrap();
    assert!(
        fixture
            .service
            .session(access_token)
            .await
            .unwrap()
            .is_some()
    );

    let (status, _, replay) = token(&fixture.app, device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(replay["error"], "invalid_grant");
    assert_eq!(replay["error_description"], "Invalid device code");
}

#[tokio::test]
async fn a_prebound_request_can_be_decided_without_the_claim_get() {
    let fixture = fixture().await;
    let issued = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/code",
        json!({"client_id":"native-client","user_id":fixture.user_id}),
        None,
    )
    .await
    .2;
    let (status, _, body) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/deny",
        json!({"userCode":issued["user_code"]}),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"success":true}));
}

#[tokio::test]
async fn default_user_codes_normalize_for_lookup_but_echo_the_submitted_spelling() {
    let fixture = fixture().await;
    let issued = issue(&fixture.app).await;
    let canonical = issued["user_code"].as_str().unwrap();
    let submitted = format!(
        "{}-{}",
        canonical[..4].to_ascii_lowercase(),
        canonical[4..].to_ascii_lowercase()
    );
    let (status, _, body) = json_request(
        &fixture.app,
        "GET",
        &format!("/api/auth/device?user_code={submitted}"),
        Value::Null,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_code"], submitted);

    insert(
        fixture.devices.as_ref(),
        record(
            "custom-device",
            "custom-code",
            None,
            DeviceCodeStatus::Pending,
        ),
    )
    .await;
    let (status, _, body) = json_request(
        &fixture.app,
        "GET",
        "/api/auth/device?user_code=CUSTOMCODE",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_description"], "Invalid user code");
}

#[tokio::test]
async fn a_decision_requires_authentication_and_a_prior_claim() {
    let fixture = fixture().await;
    let issued = issue(&fixture.app).await;
    let user_code = issued["user_code"].as_str().unwrap();
    let (status, _, body) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/approve",
        json!({"userCode":user_code}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized");
    assert_eq!(body["error_description"], "Authentication required");

    let (status, _, body) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/approve",
        json!({"userCode":user_code}),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error_description"],
        "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying"
    );
}
