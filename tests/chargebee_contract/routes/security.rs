use super::super::support::{fixture, get, post};
use async_trait::async_trait;
use axum::http::StatusCode;
use lucid_auth::{
    ChargebeeCallbackContext, ChargebeeCallbackError, ChargebeeReferenceAction,
    ChargebeeReferenceAuthorizer, ChargebeeSessionSnapshot, ChargebeeUserSnapshot,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug)]
struct RecordingAuthorizer {
    allowed: bool,
    actions: Mutex<Vec<ChargebeeReferenceAction>>,
}

#[async_trait]
impl ChargebeeReferenceAuthorizer for RecordingAuthorizer {
    async fn authorize(
        &self,
        _user: &ChargebeeUserSnapshot,
        _session: &ChargebeeSessionSnapshot,
        _reference_id: &str,
        action: ChargebeeReferenceAction,
        _context: &ChargebeeCallbackContext,
    ) -> Result<bool, ChargebeeCallbackError> {
        self.actions.lock().await.push(action);
        Ok(self.allowed)
    }
}

fn body() -> serde_json::Value {
    json!({
        "itemPriceId": "price_pro",
        "successUrl": "https://evil.example/success",
        "cancelUrl": "/pricing",
        "referenceId": "foreign-reference",
        "disableRedirect": true
    })
}

#[tokio::test]
async fn session_then_reference_authorization_then_origin_is_the_exact_order() {
    let authorizer = Arc::new(RecordingAuthorizer {
        allowed: false,
        actions: Mutex::new(Vec::new()),
    });
    let anonymous_authorizer = authorizer.clone();
    let anonymous = fixture(false, move |options| {
        options.subscription.as_mut().unwrap().authorize_reference = Some(anonymous_authorizer);
    })
    .await;
    let (status, _) = post(&anonymous, "/api/auth/subscription/create", body()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(authorizer.actions.lock().await.is_empty());

    let denied_authorizer = authorizer.clone();
    let denied = fixture(true, move |options| {
        options.subscription.as_mut().unwrap().authorize_reference = Some(denied_authorizer);
    })
    .await;
    let (status, denied_body) = post(&denied, "/api/auth/subscription/create", body()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        denied_body["message"],
        "Unauthorized access to this reference"
    );
    assert_eq!(
        *authorizer.actions.lock().await,
        [ChargebeeReferenceAction::CreateSubscription]
    );
    assert!(denied.client.calls().await.is_empty());

    let allowed = Arc::new(RecordingAuthorizer {
        allowed: true,
        actions: Mutex::new(Vec::new()),
    });
    let configured = allowed.clone();
    let origin_rejected = fixture(true, move |options| {
        options.subscription.as_mut().unwrap().authorize_reference = Some(configured);
    })
    .await;
    let (status, body) = post(&origin_rejected, "/api/auth/subscription/create", body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["message"], "The callback URL is not trusted");
    assert_eq!(
        *allowed.actions.lock().await,
        [ChargebeeReferenceAction::CreateSubscription]
    );
    assert!(origin_rejected.client.calls().await.is_empty());
}

#[tokio::test]
async fn equal_user_reference_needs_no_callback_but_a_different_one_does() {
    let fixture = fixture(true, |_| {}).await;
    let user_id = fixture.user_id.unwrap().to_string();
    let valid = json!({
        "itemPriceId": "price_pro",
        "successUrl": "/success",
        "cancelUrl": "/cancel",
        "referenceId": user_id,
        "disableRedirect": true
    });
    let (status, _) = post(&fixture, "/api/auth/subscription/create", valid).await;
    assert_eq!(status, StatusCode::OK);

    let mut different = body();
    different["successUrl"] = json!("/success");
    let (status, body) = post(&fixture, "/api/auth/subscription/create", different).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["message"],
        "referenceId not allowed without authorizeReference"
    );
}

#[tokio::test]
async fn explicit_organization_reference_is_authorized_even_when_org_billing_is_disabled() {
    let allowed = Arc::new(RecordingAuthorizer {
        allowed: true,
        actions: Mutex::new(Vec::new()),
    });
    let configured = allowed.clone();
    let fixture = fixture(true, move |options| {
        options.subscription.as_mut().unwrap().authorize_reference = Some(configured);
        assert!(!options.organization_enabled());
    })
    .await;
    let (status, body) = post(
        &fixture,
        "/api/auth/subscription/create",
        json!({
            "itemPriceId": "price_pro",
            "successUrl": "/success",
            "cancelUrl": "/cancel",
            "customerType": "organization",
            "referenceId": "not-an-organization"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Organization not found");
    assert_eq!(
        *allowed.actions.lock().await,
        [ChargebeeReferenceAction::CreateSubscription]
    );
}

#[tokio::test]
async fn reference_callbacks_receive_the_exact_action_strings() {
    let authorizer = Arc::new(RecordingAuthorizer {
        allowed: true,
        actions: Mutex::new(Vec::new()),
    });
    let configured = authorizer.clone();
    let fixture = fixture(true, move |options| {
        options.subscription.as_mut().unwrap().authorize_reference = Some(configured);
    })
    .await;
    let checkout = json!({
        "itemPriceId": "price_pro",
        "successUrl": "/success",
        "cancelUrl": "/cancel",
        "referenceId": "billing-account"
    });
    post(&fixture, "/api/auth/subscription/create", checkout.clone()).await;
    post(&fixture, "/api/auth/subscription/update", checkout).await;
    get(
        &fixture,
        "/api/auth/subscription/list?referenceId=billing-account",
    )
    .await;
    post(
        &fixture,
        "/api/auth/subscription/cancel",
        json!({"returnUrl": "/return", "referenceId": "billing-account"}),
    )
    .await;
    post(
        &fixture,
        "/api/auth/subscription/portal",
        json!({"returnUrl": "/return", "referenceId": "billing-account"}),
    )
    .await;

    let actions = authorizer.actions.lock().await;
    assert_eq!(
        actions
            .iter()
            .map(|action| action.as_str())
            .collect::<Vec<_>>(),
        [
            "create-subscription",
            "upgrade-subscription",
            "list-subscription",
            "cancel-subscription",
            "billing-portal",
        ]
    );
}
