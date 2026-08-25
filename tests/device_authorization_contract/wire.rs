use super::support::*;

#[tokio::test]
async fn code_supports_the_pinned_media_types_and_credential_headers() {
    let fixture = fixture().await;
    let issued = issue(&fixture.app).await;
    assert_eq!(issued["expires_in"], 1800);
    assert_eq!(issued["interval"], 0);
    assert_eq!(issued["verification_uri"], "http://localhost/device");
    assert!(
        issued["verification_uri_complete"]
            .as_str()
            .unwrap()
            .starts_with("http://localhost/device?user_code=")
    );

    let (status, headers, body) = request(
        &fixture.app,
        "POST",
        "/api/auth/device/code",
        Some("application/x-www-form-urlencoded"),
        Body::from("client_id=native-client&scope=openid"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::PRAGMA], "no-cache");
    assert!(serde_json::from_slice::<Value>(&body).unwrap()["device_code"].is_string());
}

#[tokio::test]
async fn generic_parser_failures_and_protocol_failures_keep_distinct_envelopes() {
    let fixture = fixture().await;
    let (status, headers, bytes) = request(
        &fixture.app,
        "POST",
        "/api/auth/device/code",
        Some("text/plain"),
        Body::from("client_id=native-client"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(headers.get(header::CACHE_CONTROL).is_none());
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({
            "message": "Content-Type \"text/plain\" is not allowed. Allowed types: application/json, application/x-www-form-urlencoded",
            "code": "UNSUPPORTED_MEDIA_TYPE"
        })
    );

    let (status, headers, body) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/code",
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get(header::CACHE_CONTROL).is_none());
    assert_eq!(
        body,
        json!({
            "error": "invalid_request",
            "error_description": "[body.client_id] Invalid input: expected string, received undefined"
        })
    );

    let (status, headers, body) = request(
        &fixture.app,
        "POST",
        "/api/auth/device/code",
        Some("application/x-www-form-urlencoded"),
        Body::from("client_id=one&client_id=two"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"error":"invalid_request","error_description":"client_id must not be repeated"})
    );
}

#[tokio::test]
async fn token_and_decision_accept_only_the_official_json_casing() {
    let fixture = fixture().await;
    let (status, _, body) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/device/approve",
        json!({"user_code": "ABCD-EFGH"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
    assert!(body["message"].as_str().unwrap().contains("body.userCode"));

    let (status, _, bytes) = request(
        &fixture.app,
        "POST",
        "/api/auth/device/token",
        Some("application/x-www-form-urlencoded"),
        Body::from(format!("grant_type={GRANT}&device_code=x&client_id=y")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["code"],
        "UNSUPPORTED_MEDIA_TYPE"
    );
}
