use super::support::{fixture, local_subscription, post_json, provider_subscription, send};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::StripeStore;
use serde_json::json;

#[tokio::test]
async fn list_cancel_restore_and_portal_use_the_local_owner_and_provider_contracts() {
    let fixture = fixture(None).await;
    fixture
        .stripe
        .set_user_customer_id(&fixture.user_id, Some("cus_owner".into()))
        .await
        .unwrap();
    let local = local_subscription(fixture.user_id.clone());
    fixture
        .stripe
        .create_subscription(local.clone())
        .await
        .unwrap();
    fixture
        .client
        .insert_subscription(provider_subscription("sub_active"))
        .await;

    let listed = send(
        &fixture.app,
        Request::get("/api/auth/subscription/list")
            .header(header::COOKIE, &fixture.cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(listed.0, StatusCode::OK);
    assert_eq!(listed.2[0]["id"], local.id.to_string());
    assert_eq!(listed.2[0]["plan"], "pro");
    assert_eq!(listed.2[0]["priceId"], "price_pro");

    let canceled = post_json(
        &fixture,
        "/api/auth/subscription/cancel",
        json!({ "returnUrl": "/account", "disableRedirect": true }),
    )
    .await;
    assert_eq!(canceled.0, StatusCode::OK);
    assert_eq!(
        canceled.2,
        json!({
            "url": "https://billing.stripe.test/session",
            "redirect": false
        })
    );

    let restored = post_json(&fixture, "/api/auth/subscription/restore", json!({})).await;
    assert_eq!(restored.0, StatusCode::OK);
    assert_eq!(restored.2["id"], "sub_active");
    assert_eq!(restored.2["cancel_at_period_end"], false);
    let stored = fixture
        .stripe
        .find_subscription(local.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.cancel_at_period_end);
    assert!(stored.cancel_at.is_none());

    let portal = post_json(
        &fixture,
        "/api/auth/subscription/billing-portal",
        json!({ "returnUrl": "/settings", "locale": "en-GB" }),
    )
    .await;
    assert_eq!(portal.0, StatusCode::OK);
    assert_eq!(portal.2["redirect"], true);
    let portal_calls = fixture.client.calls("create_billing_portal_session").await;
    assert_portal_calls(&portal_calls);
}

fn assert_portal_calls(portal_calls: &[serde_json::Value]) {
    assert_eq!(portal_calls.len(), 2);
    assert_eq!(portal_calls[0]["flow_data"]["type"], "subscription_cancel");
    assert_eq!(
        portal_calls[0]["return_url"],
        "http://localhost/api/auth/account"
    );
    assert_eq!(portal_calls[1]["customer"], "cus_owner");
    assert_eq!(
        portal_calls[1]["return_url"],
        "http://localhost/api/auth/settings"
    );
    assert_eq!(portal_calls[1]["locale"], "en-GB");
}
