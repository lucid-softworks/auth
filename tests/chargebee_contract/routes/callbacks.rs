use super::super::support::{fixture, get, get_redirect};
use axum::http::StatusCode;
use lucid_auth::{
    ChargebeeProviderSubscription, ChargebeeStore, ChargebeeSubscription,
    ChargebeeSubscriptionStatus,
};
use std::collections::BTreeMap;

#[tokio::test]
async fn success_callback_uses_exact_callback_url_casing_and_needs_no_session() {
    let fixture = fixture(false, |_| {}).await;
    let (status, location) = get_redirect(
        &fixture,
        "/api/auth/subscription/success?callbackURL=%2Fbilling%2Fcomplete",
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("http://localhost/api/auth/billing/complete")
    );

    let (status, body) = get(
        &fixture,
        "/api/auth/subscription/success?callbackUrl=%2Fignored&callbackURL=https%3A%2F%2Fevil.example",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["message"], "The callback URL is not trusted");
}

#[tokio::test]
async fn cancel_callback_checks_origin_before_optional_session() {
    let fixture = fixture(false, |_| {}).await;
    let (status, body) = get(
        &fixture,
        "/api/auth/subscription/cancel/callback?callbackURL=https%3A%2F%2Fevil.example&subscriptionId=ignored",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["message"], "The callback URL is not trusted");

    let (status, location) = get_redirect(
        &fixture,
        "/api/auth/subscription/cancel/callback?callbackURL=%2Fpricing&subscriptionId=ignored",
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("http://localhost/api/auth/pricing")
    );
    assert!(fixture.client.calls().await.is_empty());
}

#[tokio::test]
async fn authenticated_cancel_callback_reconciles_provider_cancellation() {
    let fixture = fixture(true, |_| {}).await;
    let user_id = fixture.user_id.as_deref().unwrap();
    fixture
        .store
        .set_user_customer_id(user_id, Some("customer_callback".into()))
        .await
        .unwrap();
    let mut local = ChargebeeSubscription::future(user_id);
    local.status = ChargebeeSubscriptionStatus::Active;
    local.chargebee_customer_id = Some("customer_callback".into());
    local.chargebee_subscription_id = Some("subscription_callback".into());
    let local = fixture.store.create_subscription(local).await.unwrap();
    fixture
        .client
        .set_provider_subscriptions(vec![provider_cancelled()])
        .await;

    let path = format!(
        "/api/auth/subscription/cancel/callback?callbackURL=%2Fpricing&subscriptionId={}",
        local.id
    );
    let (status, location) = get_redirect(&fixture, &path).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("http://localhost/api/auth/pricing")
    );
    let updated = fixture
        .store
        .find_subscription(local.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.status, ChargebeeSubscriptionStatus::Cancelled);
    assert_eq!(updated.canceled_at.unwrap().timestamp(), 1_700_000_000);
}

fn provider_cancelled() -> ChargebeeProviderSubscription {
    ChargebeeProviderSubscription {
        id: "subscription_callback".into(),
        customer_id: "customer_callback".into(),
        status: "cancelled".into(),
        current_term_start: None,
        current_term_end: None,
        trial_start: None,
        trial_end: None,
        cancelled_at: Some(1_700_000_000),
        subscription_items: Vec::new(),
        metadata: None,
        extra: BTreeMap::new(),
    }
}
