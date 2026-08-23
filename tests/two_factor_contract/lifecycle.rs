use super::*;

#[tokio::test]
async fn official_lifecycle_uses_exact_shapes_and_protects_factor_secrets() {
    let fixture = fixture(false, Duration::days(30), 10).await;
    let mut cookies = CookieJar::default();
    let (user_id, secret, backup_codes, enabled) = enable_totp(&fixture, &mut cookies).await;

    assert_encrypted_enrollment(&fixture, user_id, &secret, &backup_codes, &enabled).await;
    assert_totp_uri(&fixture, &mut cookies).await;
    verify_setup_and_replay(&fixture, &mut cookies, user_id, &secret, &backup_codes).await;
    disable_totp_and_enable_otp(&fixture, &mut cookies, user_id).await;
}

async fn assert_encrypted_enrollment(
    fixture: &Fixture,
    user_id: Uuid,
    secret: &str,
    backup_codes: &[String],
    enabled: &Value,
) {
    assert_eq!(enabled["method"], "totp");
    assert_eq!(enabled.as_object().unwrap().len(), 3);
    assert_eq!(backup_codes.len(), 10);
    assert!(
        enabled["totpURI"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/lucid-auth%20conformance:luna%40example.com?")
    );
    let record = fixture
        .factors
        .find_two_factor(user_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!record.enabled);
    assert!(!record.verified);
    let encrypted_secret = record.encrypted_secret.as_deref().unwrap();
    assert!(encrypted_secret.starts_with("$la$1$"));
    assert!(!encrypted_secret.contains(secret));
    let encrypted_codes = record.encrypted_backup_codes.as_deref().unwrap();
    assert!(
        backup_codes
            .iter()
            .all(|code| !encrypted_codes.contains(code))
    );
}

async fn assert_totp_uri(fixture: &Fixture, cookies: &mut CookieJar) {
    let (status, _, uri) = request(
        &fixture.app,
        cookies,
        "/api/auth/two-factor/get-totp-uri",
        json!({ "password": "correct horse battery staple" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(uri.as_object().unwrap().len(), 1);
    assert!(uri.get("totpURI").is_some());
}

async fn verify_setup_and_replay(
    fixture: &Fixture,
    cookies: &mut CookieJar,
    user_id: Uuid,
    secret: &str,
    backup_codes: &[String],
) {
    let code = fixture.service.generate_two_factor_totp(secret).unwrap();
    let (status, _, verified) = request(
        &fixture.app,
        cookies,
        "/api/auth/two-factor/verify-totp",
        json!({ "code": code, "trustDevice": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(verified["user"]["twoFactorEnabled"], true);
    assert_eq!(
        fixture
            .service
            .view_two_factor_backup_codes(user_id)
            .await
            .unwrap(),
        backup_codes
    );
    let (status, _, replayed) = request(
        &fixture.app,
        cookies,
        "/api/auth/two-factor/verify-totp",
        json!({ "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(replayed["code"], "INVALID_CODE");
}

async fn disable_totp_and_enable_otp(fixture: &Fixture, cookies: &mut CookieJar, user_id: Uuid) {
    let (status, _, disabled) = request(
        &fixture.app,
        cookies,
        "/api/auth/two-factor/disable",
        json!({ "password": "correct horse battery staple" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(disabled, json!({ "status": true }));
    assert!(
        fixture
            .factors
            .find_two_factor(user_id)
            .await
            .unwrap()
            .is_none()
    );
    let (status, _, otp_enabled) = request(
        &fixture.app,
        cookies,
        "/api/auth/two-factor/enable",
        json!({
            "password": "correct horse battery staple",
            "method": "otp"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(otp_enabled, json!({ "method": "otp" }));
}
