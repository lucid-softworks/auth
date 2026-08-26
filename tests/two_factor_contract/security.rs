use super::*;

#[tokio::test]
async fn challenge_attempts_account_lockout_and_backup_code_updates_are_atomic() {
    let fixture = fixture(true, Duration::days(30), 50).await;
    let mut cookies = CookieJar::default();
    let (user_id, _, _, _) = enable_totp(&fixture, &mut cookies).await;
    exhaust_challenge_budget(&fixture, &mut cookies).await;
    assert_backup_code_update_is_atomic(&fixture, user_id).await;
    assert_account_lockout().await;
}

async fn exhaust_challenge_budget(fixture: &Fixture, cookies: &mut CookieJar) {
    *cookies = CookieJar::default();
    let (status, _, challenge) = sign_in(&fixture.app, cookies).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        challenge,
        json!({
            "twoFactorRedirect": true,
            "twoFactorMethods": ["totp", "otp"]
        })
    );
    assert!(cookies.contains("better-auth.two_factor"));
    assert!(!cookies.contains("better-auth.session_token"));
    for _ in 0..5 {
        let (status, _, invalid) = invalid_totp(fixture, cookies).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{invalid}");
        assert_eq!(invalid["code"], "INVALID_CODE");
    }
    let (status, headers, limited) = invalid_totp(fixture, cookies).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(limited["code"], "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE");
    assert!(clears_cookie(&headers, "better-auth.two_factor"));
}

async fn invalid_totp(
    fixture: &Fixture,
    cookies: &mut CookieJar,
) -> (StatusCode, HeaderMap, Value) {
    request(
        &fixture.app,
        cookies,
        "/api/auth/two-factor/verify-totp",
        json!({ "code": "000000" }),
    )
    .await
}

async fn assert_backup_code_update_is_atomic(fixture: &Fixture, user_id: Uuid) {
    let record = fixture
        .factors
        .find_two_factor(user_id)
        .await
        .unwrap()
        .unwrap();
    let expected = record.encrypted_backup_codes;
    let (left, right) = tokio::join!(
        fixture
            .factors
            .replace_backup_codes(user_id, &expected, "replacement-left".into()),
        fixture
            .factors
            .replace_backup_codes(user_id, &expected, "replacement-right".into())
    );
    assert_eq!(usize::from(left.unwrap()) + usize::from(right.unwrap()), 1);
}

async fn assert_account_lockout() {
    let locked = fixture(false, Duration::days(30), 2).await;
    let mut cookies = CookieJar::default();
    let (_, secret, _, _) = enable_totp(&locked, &mut cookies).await;
    let setup_code = locked.service.generate_two_factor_totp(&secret).unwrap();
    let (status, _, body) = request(
        &locked.app,
        &mut cookies,
        "/api/auth/two-factor/verify-totp",
        json!({ "code": setup_code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    cookies = CookieJar::default();
    sign_in(&locked.app, &mut cookies).await;
    for _ in 0..2 {
        let (status, _, body) = invalid_totp(&locked, &mut cookies).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    let (status, _, body) = invalid_totp(&locked, &mut cookies).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "ACCOUNT_TEMPORARILY_LOCKED");
}

#[tokio::test]
async fn delivered_otp_trusts_only_a_live_rotating_device_record() {
    let fixture = fixture(true, Duration::seconds(1), 10).await;
    let mut cookies = CookieJar::default();
    enable_totp(&fixture, &mut cookies).await;
    cookies = CookieJar::default();
    let (status, _, challenge) = sign_in(&fixture.app, &mut cookies).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(challenge["twoFactorRedirect"], true);
    send_and_verify_trusted_otp(&fixture, &mut cookies).await;
    cookies.remove("better-auth.session_token");
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let (status, headers, challenged) = sign_in(&fixture.app, &mut cookies).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(challenged["twoFactorRedirect"], true);
    assert!(!cookies.contains("better-auth.trust_device"));
    assert!(clears_cookie(&headers, "better-auth.trust_device"));
}

async fn send_and_verify_trusted_otp(fixture: &Fixture, cookies: &mut CookieJar) {
    let (status, _, sent) = request(
        &fixture.app,
        cookies,
        "/api/auth/two-factor/send-otp",
        json!({ "trustDevice": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sent, json!({ "status": true }));
    let code = fixture
        .otps
        .messages
        .lock()
        .await
        .last()
        .unwrap()
        .code
        .clone();
    let (status, _, verified) = request(
        &fixture.app,
        cookies,
        "/api/auth/two-factor/verify-otp",
        json!({ "code": code, "trustDevice": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert!(cookies.contains("better-auth.trust_device"));
    assert!(cookies.contains("better-auth.session_token"));
}

fn clears_cookie(headers: &HeaderMap, name: &str) -> bool {
    headers.get_all(header::SET_COOKIE).iter().any(|value| {
        let value = value.to_str().unwrap();
        value.contains(&format!("{name}=;")) && value.contains("Max-Age=0")
    })
}
