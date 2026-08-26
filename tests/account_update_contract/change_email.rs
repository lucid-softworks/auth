use super::*;

async fn verify_current_email(fixture: &Fixture, cookie: &str, email: &str) {
    post(
        &fixture.app,
        "/api/auth/send-verification-email",
        Some(cookie),
        json!({ "email": email }),
    )
    .await;
    let token = fixture
        .mailbox
        .verification
        .lock()
        .await
        .last()
        .unwrap()
        .token
        .clone();
    let (status, _) = get(
        &fixture.app,
        &format!("/api/auth/verify-email?token={token}"),
        cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

async fn assert_wrong_session_does_not_consume_confirmation(
    fixture: &Fixture,
    cookie: &str,
    confirmation: &ChangeEmailConfirmation,
) {
    let (wrong_cookie, _) = signup(fixture, "wrong-session@example.com").await;
    let path = format!(
        "/api/auth/verify-email?token={}&callbackURL=%2Fdone",
        confirmation.token
    );
    let wrong = get_response(&fixture.app, &path, &wrong_cookie).await;
    assert_eq!(wrong.status(), StatusCode::FOUND);
    assert_eq!(
        wrong.headers()[header::LOCATION],
        "/done?error=INVALID_USER"
    );
    let confirmed = get_response(&fixture.app, &path, cookie).await;
    assert_eq!(confirmed.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn change_email_supports_immediate_and_verified_transitions() {
    let fixture = fixture(|config, _| {
        config.user.change_email.enabled = true;
        config.user.change_email.update_email_without_verification = true;
        config.session_fresh_age = chrono::Duration::nanoseconds(1);
    });
    let (cookie, _) = signup(&fixture, "immediate@example.com").await;
    let (status, body) = post(
        &fixture.app,
        "/api/auth/change-email",
        Some(&cookie),
        json!({ "newEmail": "IMMEDIATE.NEW@example.com", "callbackURL": "/done" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], true);
    let (status, same) = post(
        &fixture.app,
        "/api/auth/change-email",
        Some(&cookie),
        json!({ "newEmail": "immediate.new@example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(same["message"], "Email is the same");
    assert!(same.get("code").is_none());
    let sent = fixture.mailbox.verification.lock().await;
    let token = sent.last().unwrap().token.clone();
    assert_eq!(sent.last().unwrap().user.email, "immediate.new@example.com");
    drop(sent);
    let (status, _) = get(
        &fixture.app,
        &format!("/api/auth/verify-email?token={token}"),
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, current) = get(&fixture.app, "/api/auth/get-session", &cookie).await;
    assert_eq!(current["user"]["email"], "immediate.new@example.com");
    assert_eq!(current["user"]["emailVerified"], true);
}

#[tokio::test]
async fn verified_change_email_can_require_current_address_confirmation() {
    let fixture = fixture(|config, mailbox| {
        config.user.change_email.enabled = true;
        config.user.change_email.send_change_email_confirmation = Some(mailbox.clone());
    });
    let (cookie, _) = signup(&fixture, "confirmed@example.com").await;
    verify_current_email(&fixture, &cookie, "confirmed@example.com").await;
    let (status, _) = post(
        &fixture.app,
        "/api/auth/change-email",
        Some(&cookie),
        json!({ "newEmail": "confirmed.new@example.com", "callbackURL": "/done" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let confirmation = fixture
        .mailbox
        .confirmation
        .lock()
        .await
        .last()
        .unwrap()
        .clone();
    assert_eq!(confirmation.user.email, "confirmed@example.com");
    assert_eq!(confirmation.new_email, "confirmed.new@example.com");
    assert_wrong_session_does_not_consume_confirmation(&fixture, &cookie, &confirmation).await;
    let verification = fixture
        .mailbox
        .verification
        .lock()
        .await
        .last()
        .unwrap()
        .clone();
    assert_eq!(verification.user.email, "confirmed.new@example.com");
    let (status, body) = get(
        &fixture.app,
        &format!("/api/auth/verify-email?token={}", verification.token),
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["email"], "confirmed.new@example.com");
    assert_eq!(body["user"]["emailVerified"], true);
}

#[tokio::test]
async fn legacy_update_to_token_updates_unverified_then_sends_an_ordinary_token() {
    let fixture = fixture(|config, _| {
        config.user.change_email.enabled = true;
    });
    let (cookie, _) = signup(&fixture, "legacy-current@example.com").await;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.typ = None;
    let now = chrono::Utc::now().timestamp();
    let token = jsonwebtoken::encode(
        &header,
        &json!({
            "email": "legacy-current@example.com",
            "updateTo": "legacy-new@example.com",
            "iat": now,
            "exp": now + 3_600
        }),
        &jsonwebtoken::EncodingKey::from_secret(&[47_u8; 32]),
    )
    .unwrap();

    let (status, body) = get(
        &fixture.app,
        &format!("/api/auth/verify-email?token={token}"),
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user"]["email"], "legacy-new@example.com");
    assert_eq!(body["user"]["emailVerified"], false);

    let follow_up = fixture
        .mailbox
        .verification
        .lock()
        .await
        .last()
        .unwrap()
        .clone();
    assert_eq!(follow_up.user.email, "legacy-new@example.com");
    let payload = jsonwebtoken::dangerous::insecure_decode::<Value>(&follow_up.token)
        .unwrap()
        .claims;
    assert_eq!(payload["email"], "legacy-new@example.com");
    assert!(payload.get("updateTo").is_none());
    assert_eq!(
        payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
        3_600
    );
}

#[tokio::test]
async fn change_email_without_a_sender_matches_the_message_only_error() {
    let fixture = fixture(|config, _| {
        config.user.change_email.enabled = true;
        config.email_verification.sender = None;
    });
    let (cookie, _) = signup(&fixture, "no-sender@example.com").await;
    let (status, body) = post(
        &fixture.app,
        "/api/auth/change-email",
        Some(&cookie),
        json!({ "newEmail": "no-sender-new@example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Verification email isn't enabled");
    assert!(body.get("code").is_none());
}
