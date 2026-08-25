use super::super::support::{fixture, get, post, raw_post};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn all_eight_routes_stay_registered_with_exact_methods_when_subscriptions_are_disabled() {
    let fixture = fixture(true, |options| options.subscription = None).await;
    let checkout = json!({
        "itemPriceId": "price_pro",
        "successUrl": "/success",
        "cancelUrl": "/cancel"
    });
    let post_cases = [
        ("/api/auth/subscription/create", checkout.clone()),
        ("/api/auth/subscription/update", checkout),
        (
            "/api/auth/subscription/cancel",
            json!({"returnUrl": "/return"}),
        ),
        (
            "/api/auth/subscription/portal",
            json!({"returnUrl": "/return"}),
        ),
    ];
    for (path, body) in post_cases {
        let (status, _) = post(&fixture, path, body).await;
        assert_registered(status, path);
        assert_eq!(get(&fixture, path).await.0, StatusCode::METHOD_NOT_ALLOWED);
    }

    let get_paths = [
        "/api/auth/subscription/success?callbackURL=%2Fsuccess",
        "/api/auth/subscription/cancel/callback?callbackURL=%2Freturn",
        "/api/auth/subscription/list",
    ];
    for path in get_paths {
        let (status, _) = get(&fixture, path).await;
        assert_registered(status, path);
        assert_eq!(
            post(&fixture, path, json!({})).await.0,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    let (status, _) = raw_post(
        &fixture,
        "/api/auth/chargebee/webhook",
        &json!({"event_type": "unhandled_event", "id": "route", "content": {}}).to_string(),
        None,
    )
    .await;
    assert_registered(status, "/api/auth/chargebee/webhook");
    assert_eq!(
        get(&fixture, "/api/auth/chargebee/webhook").await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

fn assert_registered(status: StatusCode, path: &str) {
    assert_ne!(status, StatusCode::NOT_FOUND, "missing {path}");
    assert_ne!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "wrong method for {path}"
    );
}
