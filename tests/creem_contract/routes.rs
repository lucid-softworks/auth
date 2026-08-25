use super::support::{CreemCall, fixture, get, post, post_with_headers, raw_post};
use axum::http::StatusCode;
use lucid_auth::{
    CreemCallbackError, CreemStore, CreemSubscription, FnCreemWebhookCallback,
    sign_creem_webhook_text,
};
use serde_json::{Value, json};
use std::sync::Arc;

#[tokio::test]
async fn validation_precedes_the_api_key_and_the_api_key_precedes_the_session() {
    let missing_key = fixture("", false, |_| {}).await;
    let (status, body) = post(&missing_key, "/api/auth/creem/create-checkout", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({
            "code": "VALIDATION_ERROR",
            "message": "[body.productId] Invalid input: expected string, received undefined"
        })
    );

    let (status, body) = post(&missing_key, "/api/auth/creem/create-portal", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "error": "Creem API key is not configured. Please set the apiKey option when initializing the Creem plugin."
        })
    );

    let configured = fixture("creem-key", false, |_| {}).await;
    let (status, body) = post(&configured, "/api/auth/creem/create-portal", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"error": "User must be logged in"}));
    assert!(configured.transport.calls().await.is_empty());
}

#[tokio::test]
async fn anonymous_checkout_preserves_truthy_precedence_and_wire_output() {
    let fixture = fixture("creem-key", false, |_| {}).await;
    let (status, body) = post_with_headers(
        &fixture,
        "/api/auth/creem/create-checkout",
        json!({
            "productId": "product_contract",
            "customer": {"email": "anonymous@example.test"},
            "successUrl": "/complete",
            "metadata": {"referenceId": "caller", "skipTrial": "caller"},
            "customFields": [],
            "customField": [{"type": "text", "key": "ignored", "label": "Ignored"}]
        }),
        &[
            ("host", "internal.example.test"),
            ("x-forwarded-host", "forwarded.example.test"),
            ("x-forwarded-proto", "http"),
            ("x-forwarded-protocol", "https"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "redirect": true,
            "url": "https://checkout.creem.test/session"
        })
    );

    let calls = fixture.transport.calls().await;
    let CreemCall::Checkout(request) = &calls[0] else {
        panic!("expected checkout call");
    };
    assert_eq!(request.product_id, "product_contract");
    assert_eq!(
        request
            .customer
            .as_ref()
            .and_then(|customer| customer.email.as_deref()),
        Some("anonymous@example.test")
    );
    assert_eq!(
        request.success_url.as_deref(),
        Some("http://internal.example.test/complete")
    );
    assert_eq!(request.custom_fields.as_deref(), Some([].as_slice()));
    assert_eq!(request.metadata.as_ref().unwrap()["referenceId"], "caller");
    assert_eq!(request.metadata.as_ref().unwrap()["skipTrial"], "caller");
}

#[tokio::test]
async fn cancel_and_retrieve_inspect_only_the_first_matching_stored_row() {
    let fixture = fixture("creem-key", true, |_| {}).await;
    let owner = fixture.user_id.unwrap().to_string();
    let mut first = CreemSubscription::new("product_first", &owner);
    first.status = "active".into();
    let mut second = CreemSubscription::new("product_second", &owner);
    second.status = "trialing".into();
    second.creem_subscription_id = Some("stored_later".into());
    fixture.store.create_subscription(first).await.unwrap();
    fixture.store.create_subscription(second).await.unwrap();

    let (status, body) = post(
        &fixture,
        "/api/auth/creem/cancel-subscription",
        json!({"id": "caller_cancel"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["success"], true);

    let (status, body) = post(
        &fixture,
        "/api/auth/creem/retrieve-subscription",
        json!({"id": "caller_retrieve"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], "caller_retrieve");

    assert_eq!(
        fixture.transport.calls().await,
        [
            CreemCall::Cancel("caller_cancel".into()),
            CreemCall::Retrieve("caller_retrieve".into()),
        ]
    );
}

#[tokio::test]
async fn access_ignores_the_api_key_but_requires_session_and_persistence() {
    let anonymous = fixture("", false, |_| {}).await;
    let (status, body) = get(&anonymous, "/api/auth/creem/has-access-granted").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"message": "User must be logged in to check subscription status"})
    );

    let authenticated = fixture("", true, |_| {}).await;
    let mut subscription =
        CreemSubscription::new("product_access", authenticated.user_id.unwrap().to_string());
    subscription.status = "ACTIVE".into();
    authenticated
        .store
        .create_subscription(subscription.clone())
        .await
        .unwrap();
    let (status, body) = get(&authenticated, "/api/auth/creem/has-access-granted").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["hasAccessGranted"], true);
    assert_eq!(body["subscription"]["id"], subscription.id.to_string());

    let disabled = fixture("", true, |options| options.persist_subscriptions = false).await;
    let (status, body) = get(&disabled, "/api/auth/creem/has-access-granted").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "message": "Database persistence is disabled. Enable 'persistSubscriptions' option or implement custom subscription checking."
        })
    );
}

#[tokio::test]
async fn handler_keeps_provider_success_and_error_results_at_outer_http_200() {
    let fixture = fixture("creem-key", false, |_| {}).await;
    fixture.transport.set_checkout_url(None).await;
    let (status, body) = post(
        &fixture,
        "/api/auth/creem/create-checkout",
        json!({"productId": "without_url"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"redirect": true}));

    fixture.transport.fail_next("provider exploded").await;
    let (status, body) = post(
        &fixture,
        "/api/auth/creem/create-checkout",
        json!({"productId": "provider_error"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"error": "Failed to create checkout"}));
}

#[tokio::test]
async fn webhook_signature_success_and_failures_are_handler_http_200() {
    let webhook_fixture = fixture("creem-key", false, |options| {
        options.webhook_secret = Some("whsec_contract".into());
    })
    .await;
    let payload = json!({
        "eventType": "refund.created",
        "id": "event_contract",
        "created_at": 1.5,
        "object": {"object": "refund", "id": "refund_contract"}
    })
    .to_string();
    let signature = sign_creem_webhook_text(&payload, "whsec_contract");

    let (status, body) = raw_post(
        &webhook_fixture,
        "/api/auth/creem/webhook",
        &payload,
        Some(&signature),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"message": "Webhook received"}));

    let (status, body) = raw_post(
        &webhook_fixture,
        "/api/auth/creem/webhook",
        &payload,
        Some("invalid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"error": "Invalid signature"}));

    let failing = fixture("creem-key", false, |options| {
        options.webhook_secret = Some("whsec_contract".into());
        options.callbacks.on_refund_created = Some(Arc::new(FnCreemWebhookCallback::new(
            |_payload: Value| async { Err(CreemCallbackError::new("callback exploded")) },
        )));
    })
    .await;
    let (status, body) = raw_post(
        &failing,
        "/api/auth/creem/webhook",
        &payload,
        Some(&signature),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"error": "Failed to process webhook"}));
}
