use super::{
    flow::begin_proxy_flow,
    support::{
        APP_ORIGIN, PREVIEW_ORIGIN, PRODUCTION_ORIGIN, PROXY_SECRET, encrypt_json, fixture,
        query_value, response_json, response_text, send,
    },
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use lucid_auth::{OAuthProxyConfig, OAuthProxySecret};
use serde_json::json;
use url::Url;

fn config(max_age: Duration) -> OAuthProxyConfig {
    OAuthProxyConfig {
        current_url: Some(Url::parse(PREVIEW_ORIGIN).unwrap()),
        production_url: Some(Url::parse(PRODUCTION_ORIGIN).unwrap()),
        max_age,
        secret: Some(OAuthProxySecret::from(PROXY_SECRET.to_vec())),
    }
}

fn encoded(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn location(response: &axum::response::Response) -> &str {
    response.headers()[header::LOCATION].to_str().unwrap()
}

async fn assert_initial_endpoint_errors(fixture: &super::support::Fixture) {
    let endpoint = "/api/auth/oauth-proxy-callback";
    let untrusted = send(
        &fixture.app,
        Request::get(format!(
            "{endpoint}?callbackURL={}",
            encoded("https://evil.example.test/done")
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(untrusted.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(untrusted).await,
        json!({"code":"INVALID_CALLBACK_URL","message":"Invalid callbackURL"})
    );

    let callback = format!("{APP_ORIGIN}/complete");
    let missing = send(
        &fixture.app,
        Request::get(format!("{endpoint}?callbackURL={}", encoded(&callback)))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::FOUND);
    assert_eq!(
        location(&missing),
        format!("{PREVIEW_ORIGIN}/api/auth/error?error=missing_profile")
    );

    let invalid = send(
        &fixture.app,
        Request::get(format!(
            "{endpoint}?callbackURL={}&profile=not-encrypted",
            encoded(&callback)
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::FOUND);
    assert_eq!(
        location(&invalid),
        format!("{PREVIEW_ORIGIN}/api/auth/error?error=invalid_profile")
    );

    let malformed_profile = encrypt_json(PROXY_SECRET, &json!({}));
    let malformed = send(
        &fixture.app,
        Request::get(format!(
            "{endpoint}?callbackURL={}&profile={}",
            encoded(&callback),
            encoded(&malformed_profile)
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::FOUND);
    assert_eq!(
        location(&malformed),
        format!("{PREVIEW_ORIGIN}/api/auth/error?error=invalid_payload")
    );
}

async fn assert_profile_age_errors(fixture: &super::support::Fixture) {
    let endpoint = "/api/auth/oauth-proxy-callback";
    let callback = format!("{APP_ORIGIN}/complete");
    for (name, timestamp) in [
        ("expired", Utc::now().timestamp_millis() - 5_100),
        ("future", Utc::now().timestamp_millis() + 10_100),
    ] {
        let error_url = format!("{APP_ORIGIN}/{name}-error");
        let profile = encrypt_json(
            PROXY_SECRET,
            &json!({
                "userInfo": {
                    "id": "subject",
                    "email": "payload@example.com",
                    "name": "Payload"
                },
                "account": {
                    "providerId": "fixture",
                    "issuer": "https://issuer.fixture",
                    "accountId": "subject"
                },
                "state": "unissued-state",
                "callbackURL": callback,
                "errorURL": error_url,
                "timestamp": timestamp
            }),
        );
        let response = send(
            &fixture.app,
            Request::get(format!(
                "{endpoint}?callbackURL={}&profile={}",
                encoded(&callback),
                encoded(&profile)
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            location(&response),
            format!("{error_url}?error=payload_expired")
        );
    }
}

async fn assert_unissued_state_error(fixture: &super::support::Fixture) {
    let endpoint = "/api/auth/oauth-proxy-callback";
    let callback = format!("{APP_ORIGIN}/complete");
    let state_error_url = format!("{APP_ORIGIN}/state-error");
    let unissued = encrypt_json(
        PROXY_SECRET,
        &json!({
            "userInfo": {
                "id": "subject",
                "email": "payload@example.com",
                "name": "Payload"
            },
            "account": {
                "providerId": "fixture",
                "issuer": "https://issuer.fixture",
                "accountId": "subject"
            },
            "state": "unissued-state",
            "callbackURL": callback,
            "errorURL": state_error_url,
            "timestamp": Utc::now().timestamp_millis()
        }),
    );
    let state_mismatch = send(
        &fixture.app,
        Request::get(format!(
            "{endpoint}?callbackURL={}&profile={}",
            encoded(&callback),
            encoded(&unissued)
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(state_mismatch.status(), StatusCode::FOUND);
    assert_eq!(
        location(&state_mismatch),
        format!("{state_error_url}?error=state_mismatch")
    );
}

#[tokio::test]
async fn endpoint_rejects_untrusted_missing_malformed_and_expired_profiles_exactly() {
    let fixture = fixture(PREVIEW_ORIGIN, b'Q', config(Duration::seconds(5)));
    assert_initial_endpoint_errors(&fixture).await;
    assert_profile_age_errors(&fixture).await;
    assert_unissued_state_error(&fixture).await;
}

#[tokio::test]
async fn production_callback_uses_the_pinned_redirect_errors_and_drops_description() {
    let preview = fixture(PREVIEW_ORIGIN, b'V', config(Duration::seconds(60)));
    let production = fixture(
        PRODUCTION_ORIGIN,
        b'D',
        OAuthProxyConfig {
            current_url: Some(Url::parse(PRODUCTION_ORIGIN).unwrap()),
            production_url: Some(Url::parse(PRODUCTION_ORIGIN).unwrap()),
            max_age: Duration::seconds(60),
            secret: Some(OAuthProxySecret::from(PROXY_SECRET.to_vec())),
        },
    );
    let (sign_in, _) = begin_proxy_flow(&preview.app).await;
    let state = query_value(sign_in["url"].as_str().unwrap(), "state");
    let error_url = format!("{APP_ORIGIN}/oauth-error");

    let denied = send(
        &production.app,
        Request::get(format!(
            "/api/auth/callback/fixture?error=access_denied&error_description={}&state={}",
            encoded("user denied access"),
            encoded(&state)
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FOUND);
    assert_eq!(
        location(&denied),
        format!("{error_url}?error=access_denied")
    );

    let no_code = send(
        &production.app,
        Request::get(format!(
            "/api/auth/callback/fixture?state={}",
            encoded(&state)
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(no_code.status(), StatusCode::FOUND);
    assert_eq!(location(&no_code), format!("{error_url}?error=no_code"));

    let invalid_code = send(
        &production.app,
        Request::get(format!(
            "/api/auth/callback/fixture?code=wrong&state={}",
            encoded(&state)
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(invalid_code.status(), StatusCode::FOUND);
    assert_eq!(
        location(&invalid_code),
        format!("{error_url}?error=invalid_code")
    );

    assert!(response_text(invalid_code).await.is_empty());
}
