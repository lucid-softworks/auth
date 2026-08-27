use super::support::{
    application, body_json, challenge, cookie_header, set_cookies, sign_up_request,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use lucid_auth::VerificationValue;
use serde_json::json;
use tower::ServiceExt as _;

#[tokio::test]
async fn plugin_disabled_routes_are_absent_and_electron_origin_is_never_bridged() {
    let (disabled, _, _) = application(false, false);
    assert_eq!(
        disabled
            .oneshot(
                Request::post("/api/auth/electron/token")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    let (enabled, _, _) = application(true, false);
    let mut spoofed_request = sign_up_request(None, Some(("electron-origin", "myapp:/")));
    spoofed_request
        .headers_mut()
        .insert("sec-fetch-site", "same-origin".parse().unwrap());
    let spoofed = enabled.oneshot(spoofed_request).await.unwrap();
    assert_eq!(spoofed.status(), StatusCode::FORBIDDEN);
    assert_ne!(body_json(spoofed).await["code"], "INVALID_ORIGIN");

    let (enabled, _, _) = application(true, false);
    let untrusted = enabled
        .oneshot(
            Request::post(
                "/api/auth/electron/transfer-user?client_id=electron&state=s&code_challenge=c",
            )
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, "better-auth.session_token=not-a-session")
            .header(header::ORIGIN, "https://untrusted.example")
            .body(Body::from("{}"))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(untrusted.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(untrusted).await["code"], "INVALID_ORIGIN");
}

#[tokio::test]
async fn token_exchange_rejects_aliases_plaintext_and_malformed_records() {
    let (app, service, _) = application(true, false);
    let wrong_case = app
        .clone()
        .oneshot(
            Request::post("/api/auth/electron/token")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "myapp:/")
                .body(Body::from(
                    json!({
                        "token": "token",
                        "state": "state",
                        "codeVerifier": "alias"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_case.status(), StatusCode::BAD_REQUEST);

    service
        .create_verification_value(VerificationValue::new(
            "electron:plaintext",
            json!({
                "userId": "missing",
                "codeChallenge": "raw-verifier",
                "state": "state"
            })
            .to_string(),
            Utc::now() + Duration::minutes(1),
        ))
        .await
        .unwrap();
    let plaintext = exchange(&app, "plaintext", "state", "raw-verifier").await;
    assert_eq!(plaintext.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(plaintext).await["code"], "INVALID_CODE_VERIFIER");
    assert_eq!(
        exchange(&app, "plaintext", "state", "raw-verifier")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    service
        .create_verification_value(VerificationValue::new(
            "electron:malformed",
            "not-json",
            Utc::now() + Duration::minutes(1),
        ))
        .await
        .unwrap();
    let malformed = exchange(&app, "malformed", "state", "verifier").await;
    assert_eq!(malformed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body_json(malformed).await,
        json!({
            "code": "INVALID_TOKEN", "message": "Invalid or expired token."
        })
    );
}

#[tokio::test]
async fn state_challenge_user_and_expiry_errors_keep_exact_statuses() {
    let (app, service, _) = application(true, false);
    service
        .create_verification_value(VerificationValue::new(
            "electron:missing-challenge",
            json!({ "userId": "missing", "state": "state" }).to_string(),
            Utc::now() + Duration::minutes(1),
        ))
        .await
        .unwrap();
    let missing = exchange(&app, "missing-challenge", "state", "verifier").await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(missing).await["code"], "MISSING_CODE_CHALLENGE");

    service
        .create_verification_value(VerificationValue::new(
            "electron:missing-user",
            json!({
                "userId": "does-not-exist",
                "codeChallenge": challenge("verifier"),
                "state": "state"
            })
            .to_string(),
            Utc::now() + Duration::minutes(1),
        ))
        .await
        .unwrap();
    let user = exchange(&app, "missing-user", "state", "verifier").await;
    assert_eq!(user.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body_json(user).await["code"], "USER_NOT_FOUND");

    service
        .create_verification_value(VerificationValue::new(
            "electron:expired",
            json!({
                "userId": "missing",
                "codeChallenge": challenge("verifier"),
                "state": "state"
            })
            .to_string(),
            Utc::now() - Duration::seconds(1),
        ))
        .await
        .unwrap();
    let expired = exchange(&app, "expired", "state", "verifier").await;
    assert_eq!(expired.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(expired).await["code"], "INVALID_TOKEN");
}

#[tokio::test]
async fn transfer_enforces_exact_client_state_and_pkce_inputs() {
    let (app, _, _) = application(true, false);
    let signed_up = app
        .clone()
        .oneshot(sign_up_request(
            None,
            Some((header::ORIGIN.as_str(), "myapp:/")),
        ))
        .await
        .unwrap();
    let cookie = cookie_header(&set_cookies(&signed_up));

    for (query, code, message) in [
        (
            "client_id=wrong&state=state&code_challenge=challenge",
            "INVALID_CLIENT_ID",
            "Invalid client ID",
        ),
        (
            "client_id=electron&state=&code_challenge=challenge",
            "MISSING_STATE",
            "state is required",
        ),
        (
            "client_id=electron&state=state&code_challenge=",
            "MISSING_PKCE",
            "pkce is required",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/api/auth/electron/transfer-user?{query}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ORIGIN, "myapp:/")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await,
            json!({ "code": code, "message": message })
        );
    }
}

async fn exchange(
    app: &axum::Router,
    token: &str,
    state: &str,
    verifier: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::post("/api/auth/electron/token")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "myapp:/")
                .body(Body::from(
                    json!({
                        "token": token,
                        "state": state,
                        "code_verifier": verifier
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}
