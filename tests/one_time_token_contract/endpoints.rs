use super::support::{
    fixture, generate, generated_token, json_body, session_cookie, signup, verify,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use lucid_auth::{AuthStore, OneTimeTokenConfig, OneTimeTokenRequestContext, VerificationStore};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn assert_error(response: axum::response::Response, message: &str) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await,
        json!({ "code": "BAD_REQUEST", "message": message })
    );
}

#[tokio::test]
async fn generation_requires_an_ordinary_session_and_disable_client_request_is_http_only() {
    let enabled = fixture(OneTimeTokenConfig::default());
    let response = generate(&enabled.app, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(response).await,
        json!({ "code": "UNAUTHORIZED", "message": "Unauthorized" })
    );

    let disabled = fixture(OneTimeTokenConfig {
        disable_client_request: true,
        ..OneTimeTokenConfig::default()
    });
    let response = generate(&disabled.app, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["code"], "UNAUTHORIZED");
    let credential = signup(&disabled, "server-only").await;
    assert_error(
        generate(&disabled.app, Some(&credential.cookie)).await,
        "Client requests are disabled",
    )
    .await;

    let session = disabled
        .service
        .session(&credential.token)
        .await
        .unwrap()
        .unwrap();
    let token = disabled
        .service
        .generate_one_time_token(&session, OneTimeTokenRequestContext::default())
        .await
        .unwrap();
    assert!(!token.is_empty());
}

#[tokio::test]
async fn verification_is_a_portable_session_handoff_and_strips_unknown_fields() {
    let fixture = fixture(OneTimeTokenConfig::default());
    let source = signup(&fixture, "source").await;
    let receiver = signup(&fixture, "receiver").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;

    let response = super::support::verify_body(
        &fixture.app,
        json!({ "token": token, "purpose": "ignored", "payload": { "ignored": true } }),
        Some(&receiver.cookie),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = session_cookie(&response).expect("verification sets the source session cookie");
    assert_ne!(cookie, receiver.cookie);
    let body = json_body(response).await;
    assert_eq!(body["user"]["id"], source.user_id.to_string());
    assert_eq!(body["session"]["id"], source.session_id.to_string());

    assert_error(verify(&fixture.app, &token, None).await, "Invalid token").await;
}

#[tokio::test]
async fn disable_set_session_cookie_changes_only_cookie_binding() {
    let fixture = fixture(OneTimeTokenConfig {
        disable_set_session_cookie: true,
        ..OneTimeTokenConfig::default()
    });
    let source = signup(&fixture, "cookie-disabled").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    let response = verify(&fixture.app, &token, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(session_cookie(&response).is_none());
    let body = json_body(response).await;
    assert_eq!(body["user"]["id"], source.user_id.to_string());
    assert_eq!(body["session"]["id"], source.session_id.to_string());
}

#[tokio::test]
async fn invalid_expired_and_replayed_verification_values_share_the_exact_error() {
    let fixture = fixture(OneTimeTokenConfig::default());
    assert_error(
        verify(&fixture.app, "never-issued", None).await,
        "Invalid token",
    )
    .await;

    let source = signup(&fixture, "expired-token").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    let mut record = fixture
        .service
        .find_verification_value(&format!("one-time-token:{token}"))
        .await
        .unwrap()
        .unwrap();
    record.expires_at = Utc::now() - Duration::seconds(1);
    fixture.store.update_verification(record).await.unwrap();
    assert_error(verify(&fixture.app, &token, None).await, "Invalid token").await;
    assert_error(verify(&fixture.app, &token, None).await, "Invalid token").await;
}

#[tokio::test]
async fn a_missing_referenced_session_burns_the_token_before_lookup() {
    let fixture = fixture(OneTimeTokenConfig::default());
    let source = signup(&fixture, "deleted-session").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    fixture.store.delete_session(&source.token).await.unwrap();

    assert_error(
        verify(&fixture.app, &token, None).await,
        "Session not found",
    )
    .await;
    assert_error(verify(&fixture.app, &token, None).await, "Invalid token").await;
}

#[tokio::test]
async fn expired_session_error_retains_the_cookie_and_burns_the_token() {
    let fixture = fixture(OneTimeTokenConfig::default());
    let source = signup(&fixture, "expired-session").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    fixture
        .store
        .expire_session(source.session_id, Utc::now() - Duration::seconds(1))
        .await
        .unwrap();

    let expired = verify(&fixture.app, &token, None).await;
    assert_eq!(expired.status(), StatusCode::BAD_REQUEST);
    assert!(session_cookie(&expired).is_some());
    assert_eq!(
        json_body(expired).await,
        json!({ "code": "BAD_REQUEST", "message": "Session expired" })
    );
    assert_error(verify(&fixture.app, &token, None).await, "Invalid token").await;
}

#[tokio::test]
async fn malformed_bodies_follow_the_shared_validation_contract() {
    let fixture = fixture(OneTimeTokenConfig::default());
    for body in [json!({}), json!({ "token": 42 }), Value::Null] {
        let response = super::support::verify_body(&fixture.app, body, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "VALIDATION_ERROR");
    }

    let invalid_json = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/one-time-token/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_json.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(invalid_json).await,
        json!({ "code": "BAD_REQUEST", "message": "Invalid JSON in request body" })
    );

    let unsupported = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/one-time-token/verify")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        json_body(unsupported).await,
        json!({
            "code": "UNSUPPORTED_MEDIA_TYPE",
            "message": "Content-Type \"text/plain\" is not allowed. Allowed types: application/json"
        })
    );
}
