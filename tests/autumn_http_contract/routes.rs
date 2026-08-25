use super::support::{
    FakeAutumnClient, app_with_options, fixture, organization_fixture, post, user_fixture,
};
use axum::http::StatusCode;
use lucid_auth::{
    AutumnCustomerScope, AutumnIdentity, AutumnIdentityError, AutumnOperation, AutumnOptions,
    AutumnProviderError, FnAutumnIdentityProvider,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn authenticated_identity_overwrites_all_public_customer_fields() {
    let fixture = fixture().await;
    let (status, body) = post(
        &fixture.app,
        "/api/auth/autumn/attach",
        Some(&fixture.cookie),
        Some(json!({
            "planId": "pro",
            "customerId": "attacker",
            "customerData": {"customerId": "attacker"},
            "name": "Attacker",
            "email": "attacker@example.com",
            "stripeId": "stripe_attacker"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let calls = fixture.client.calls().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, AutumnOperation::Attach);
    assert_eq!(calls[0].1["customerId"], fixture.user_id.to_string());
    assert_eq!(calls[0].1["planId"], "pro");
    assert!(calls[0].1.get("customerData").is_none());
    assert!(calls[0].1.get("name").is_none());
    assert_eq!(calls[0].2, "autumn_contract_key");
    assert_eq!(calls[0].3.as_str(), "https://autumn.example.test/prefix");
}

#[tokio::test]
async fn list_plans_accepts_an_omitted_body_without_a_session() {
    let fixture = fixture().await;
    let (status, body) = post(&fixture.app, "/api/auth/autumn/listPlans", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let calls = fixture.client.calls().await;
    assert_eq!(calls[0].0, AutumnOperation::ListPlans);
    assert_eq!(calls[0].1, json!({}));
}

#[tokio::test]
async fn missing_customer_and_get_or_create_opt_out_never_call_provider() {
    let fixture = fixture().await;
    let (status, body) = post(
        &fixture.app,
        "/api/auth/autumn/attach",
        None,
        Some(json!({"planId": "pro"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["code"], "no_customer_id");
    assert_eq!(body["statusCode"], 401);

    let (status, body) = post(
        &fixture.app,
        "/api/auth/autumn/getOrCreateCustomer",
        None,
        Some(json!({"errorOnNotFound": false})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::Value::Null);
    assert!(fixture.client.calls().await.is_empty());
}

#[tokio::test]
async fn validation_precedes_missing_secret_and_missing_secret_precedes_provider() {
    // SAFETY: this test does not mutate the process environment and relies on
    // the test runner not defining an Autumn credential.
    assert!(std::env::var_os("AUTUMN_SECRET_KEY").is_none());
    let client = Arc::new(FakeAutumnClient::default());
    let callback_count = Arc::new(AtomicUsize::new(0));
    let count = callback_count.clone();
    let identify = FnAutumnIdentityProvider::new(
        move |_: Option<lucid_auth::SessionWithUser>, _: Option<lucid_auth::Organization>| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(Some(AutumnIdentity::new("must-not-run")))
            }
        },
    );
    let mut options = AutumnOptions::with_client(client.clone());
    options.identify = Some(Arc::new(identify));
    let app = app_with_options(options, [83_u8; 32]);

    let (status, body) = post(&app, "/api/auth/autumn/getEntity", None, Some(json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({
            "message": "[body.entityId] Invalid input: expected string, received undefined",
            "code": "VALIDATION_ERROR"
        })
    );

    let (status, body) = post(&app, "/api/auth/autumn/listPlans", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "message": "Autumn secret key not found in ENV variables or passed into autumnHandler",
            "code": "no_secret_key",
            "statusCode": 500
        })
    );
    assert_eq!(callback_count.load(Ordering::SeqCst), 0);
    assert!(client.calls().await.is_empty());
}

#[tokio::test]
async fn custom_identity_fully_overrides_scope_and_runs_for_list_plans() {
    let client = Arc::new(FakeAutumnClient::default());
    let callback_count = Arc::new(AtomicUsize::new(0));
    let count = callback_count.clone();
    let identify = FnAutumnIdentityProvider::new(
        move |session: Option<lucid_auth::SessionWithUser>,
              organization: Option<lucid_auth::Organization>| {
            let count = count.clone();
            async move {
                assert!(session.is_none());
                assert!(organization.is_none());
                count.fetch_add(1, Ordering::SeqCst);
                Ok(Some(AutumnIdentity::new("custom-customer")))
            }
        },
    );
    let mut options = AutumnOptions::with_client(client.clone());
    options.secret_key = Some("custom_identity_key".into());
    options.identify = Some(Arc::new(identify));
    let app = app_with_options(options, [84_u8; 32]);

    let (status, body) = post(&app, "/api/auth/autumn/listPlans", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post(&app, "/api/auth/autumn/listEvents", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post(
        &app,
        "/api/auth/autumn/attach",
        None,
        Some(json!({"planId": "pro"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(callback_count.load(Ordering::SeqCst), 3);
    let calls = client.calls().await;
    assert_eq!(calls[0].1["customerId"], "custom-customer");
    assert_eq!(calls[1].1["customerId"], "custom-customer");
    assert_eq!(calls[2].1["customerId"], "custom-customer");
}

#[tokio::test]
async fn custom_identity_failure_is_an_adapter_error_and_skips_provider() {
    let client = Arc::new(FakeAutumnClient::default());
    let identify = FnAutumnIdentityProvider::new(
        |_: Option<lucid_auth::SessionWithUser>, _: Option<lucid_auth::Organization>| async {
            Err(AutumnIdentityError::new("identity exploded"))
        },
    );
    let mut options = AutumnOptions::with_client(client.clone());
    options.secret_key = Some("custom_identity_key".into());
    options.identify = Some(Arc::new(identify));
    let app = app_with_options(options, [85_u8; 32]);

    let (status, body) = post(&app, "/api/auth/autumn/listPlans", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "message": "identity exploded",
            "code": "internal_error",
            "statusCode": 500
        })
    );
    assert!(client.calls().await.is_empty());
}

#[tokio::test]
async fn organization_scope_uses_only_the_active_organization() {
    let (fixture, organization_id) = organization_fixture(AutumnCustomerScope::Organization).await;
    let (status, body) = post(
        &fixture.app,
        "/api/auth/autumn/attach",
        Some(&fixture.cookie),
        Some(json!({"planId": "organization-plan"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let calls = fixture.client.calls().await;
    assert_eq!(calls[0].1["customerId"], organization_id.to_string());
}

#[tokio::test]
async fn organization_first_scope_falls_back_to_the_user_without_organization_plugin() {
    let fixture = user_fixture(AutumnCustomerScope::UserAndOrganization).await;
    let (status, body) = post(
        &fixture.app,
        "/api/auth/autumn/attach",
        Some(&fixture.cookie),
        Some(json!({"planId": "fallback"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let calls = fixture.client.calls().await;
    assert_eq!(calls[0].1["customerId"], fixture.user_id.to_string());
}

#[tokio::test]
async fn provider_status_is_kept_in_the_body_while_better_auth_emits_http_200() {
    let fixture = fixture().await;
    fixture
        .client
        .fail_next(AutumnProviderError::new(
            Some(422),
            "provider rejected request",
            "provider_code",
        ))
        .await;
    let (status, body) = post(
        &fixture.app,
        "/api/auth/autumn/attach",
        Some(&fixture.cookie),
        Some(json!({"planId": "invalid-provider-plan"})),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "message": "provider rejected request",
            "code": "provider_code",
            "statusCode": 422
        })
    );
}
