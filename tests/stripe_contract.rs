use lucid_auth::{
    AuthPlugin, CustomerType, MemoryStripeStore, PluginHttpMethod, StaticPlans, StripeErrorCode,
    StripeHttpClient, StripeModelSchema, StripeOptions, StripePlan, StripePlugin, StripeSchema,
    StripeStore, Subscription, SubscriptionConfiguration, SubscriptionOptions, SubscriptionStatus,
    SubscriptionSuccessQuery, UpgradeSubscriptionInput, endpoint_metadata, schema_tables,
};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

#[test]
fn webhook_only_plugin_metadata_matches_1_7_1() {
    let plugin = StripePlugin::new(
        StripeOptions::new(
            Arc::new(StripeHttpClient::new("sk_test_contract")),
            "whsec_contract",
        ),
        Arc::new(MemoryStripeStore::new()),
    );
    let descriptor = plugin.descriptor();

    assert_eq!(descriptor.id, "stripe");
    assert_eq!(descriptor.version, "1.7.2");
    assert_eq!(descriptor.endpoints.len(), 1);
    assert_eq!(descriptor.endpoints[0].path, "/stripe/webhook");
    assert_eq!(descriptor.endpoints[0].method, PluginHttpMethod::Post);
    assert_eq!(descriptor.endpoints[0].client_method, "stripeWebhook");

    let client = descriptor
        .client
        .expect("Stripe has official client metadata");
    assert_eq!(client.package, "@better-auth/stripe");
    assert_eq!(client.import_path, "@better-auth/stripe/client");
    assert_eq!(client.factory, "stripeClient");
    assert_eq!(client.better_auth_version, Some("1.7.2"));
    assert_eq!(client.client_id, Some("stripe-client"));
    assert_eq!(client.client_version, Some("1.7.2"));
}

#[test]
fn subscription_endpoint_inventory_matches_1_7_1() {
    let mut enabled_options = StripeOptions::new(
        Arc::new(StripeHttpClient::new("sk_test_contract")),
        "whsec_contract",
    );
    enabled_options.subscription =
        SubscriptionConfiguration::Enabled(SubscriptionOptions::new(Arc::new(StaticPlans(vec![
            plan("Pro"),
        ]))));
    let enabled = StripePlugin::new(enabled_options, Arc::new(MemoryStripeStore::new()));
    let endpoints = enabled.descriptor().endpoints;

    assert_eq!(endpoints.len(), 7);
    assert_eq!(
        endpoints
            .iter()
            .map(|endpoint| (
                endpoint.method,
                endpoint.path.as_ref(),
                endpoint.client_method
            ))
            .collect::<Vec<_>>(),
        vec![
            (PluginHttpMethod::Post, "/stripe/webhook", "stripeWebhook"),
            (
                PluginHttpMethod::Post,
                "/subscription/upgrade",
                "subscription.upgrade"
            ),
            (
                PluginHttpMethod::Post,
                "/subscription/cancel",
                "subscription.cancel"
            ),
            (
                PluginHttpMethod::Post,
                "/subscription/restore",
                "subscription.restore"
            ),
            (
                PluginHttpMethod::Get,
                "/subscription/list",
                "subscription.list"
            ),
            (
                PluginHttpMethod::Get,
                "/subscription/success",
                "subscription.success"
            ),
            (
                PluginHttpMethod::Post,
                "/subscription/billing-portal",
                "subscription.billingPortal",
            ),
        ]
    );
}

#[test]
fn endpoint_runtime_metadata_preserves_hidden_raw_webhook_and_success_exception() {
    let endpoints = endpoint_metadata(true);
    let webhook = &endpoints[0];
    assert_eq!(webhook.operation_id, "handleStripeWebhook");
    assert!(webhook.hidden);
    assert!(webhook.clone_request);
    assert!(!webhook.body_parsing);
    assert!(!webhook.session_required);
    assert!(webhook.client_action.is_none());

    let success = endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/success")
        .expect("success endpoint is inferred when subscriptions are enabled");
    assert_eq!(success.operation_id, "handleSubscriptionSuccess");
    assert!(!success.session_required);
    assert!(success.reference_action.is_none());
    assert_eq!(success.origin_fields[0].as_str(), "callbackURL");
}

#[test]
fn request_defaults_and_success_query_accept_only_upstream_casing() {
    let upgrade: UpgradeSubscriptionInput =
        serde_json::from_value(json!({ "plan": "Pro" })).expect("minimal upgrade body");
    assert_eq!(upgrade.success_url, "/");
    assert_eq!(upgrade.cancel_url, "/");
    assert_eq!(upgrade.effective_customer_type(), CustomerType::User);
    assert!(!upgrade.schedule_at_period_end);
    assert!(!upgrade.disable_redirect);

    let success: SubscriptionSuccessQuery = serde_json::from_value(json!({
        "callbackURL": "/done/{CHECKOUT_SESSION_ID}/{CHECKOUT_SESSION_ID}",
        "checkoutSessionId": "cs_exact",
        "callbackUrl": "/wrong",
        "callback_url": "/also-wrong"
    }))
    .expect("success accepts arbitrary query keys");
    assert_eq!(
        success.callback_url(),
        Some("/done/{CHECKOUT_SESSION_ID}/{CHECKOUT_SESSION_ID}")
    );
    assert_eq!(
        success.callback_with_checkout_session().as_deref(),
        Some("/done/cs_exact/cs_exact")
    );

    let aliases_only: SubscriptionSuccessQuery = serde_json::from_value(json!({
        "callbackUrl": "/wrong",
        "callback_url": "/also-wrong",
        "checkout_session_id": "cs_wrong"
    }))
    .unwrap();
    assert_eq!(aliases_only.effective_callback_url(), "/");
    assert!(aliases_only.checkout_session_id().is_none());
}

#[test]
fn conditional_schema_is_remappable_and_never_persists_plan_configuration() {
    let disabled_remap = StripeSchema {
        subscription: StripeModelSchema {
            model_name: Some("ignored_subscription".into()),
            fields: BTreeMap::from([("notAnUpstreamField".into(), "ignored".into())]),
        },
        ..StripeSchema::default()
    };
    let disabled = schema_tables(&disabled_remap, false, false);
    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0].logical_name, "user");

    let schema = StripeSchema {
        organization: StripeModelSchema {
            model_name: Some("billing_organizations".into()),
            fields: BTreeMap::from([("stripeCustomerId".into(), "billing_customer_id".into())]),
        },
        subscription: StripeModelSchema {
            model_name: Some("billing_subscriptions".into()),
            fields: BTreeMap::from([("referenceId".into(), "owner_reference".into())]),
        },
        ..StripeSchema::default()
    };
    let tables = schema_tables(&schema, true, true);
    assert_eq!(
        tables
            .iter()
            .map(|table| table.logical_name.as_str())
            .collect::<Vec<_>>(),
        ["subscription", "user", "organization"]
    );
    assert_eq!(
        tables[0].model_name.as_deref(),
        Some("billing_subscriptions")
    );
    assert_eq!(
        tables[0].fields["referenceId"].field_name.as_deref(),
        Some("owner_reference")
    );
    assert_eq!(
        tables[2].model_name.as_deref(),
        Some("billing_organizations")
    );
    assert_eq!(
        tables[2].fields["stripeCustomerId"].field_name.as_deref(),
        Some("billing_customer_id")
    );
    assert!(!tables[0].fields.contains_key("limits"));
    assert!(!tables[0].fields.contains_key("paymentMethod"));
    assert!(!tables[0].fields.contains_key("webhookEvent"));
}

#[tokio::test]
async fn memory_store_preserves_adapter_order_non_unique_references_and_reverse_customer_links() {
    let store = MemoryStripeStore::new();
    let user_id = Uuid::new_v4().to_string();
    let organization_id = Uuid::new_v4().to_string();
    store
        .set_user_customer_id(&user_id, Some("cus_user".into()))
        .await
        .unwrap();
    store
        .set_organization_customer_id(organization_id.clone(), Some("cus_org".into()))
        .await
        .unwrap();
    assert_eq!(
        store.user_id_by_customer("cus_user").await.unwrap(),
        Some(user_id)
    );
    assert_eq!(
        store.organization_id_by_customer("cus_org").await.unwrap(),
        Some(organization_id)
    );

    let first = subscription("shared", "cus_user", SubscriptionStatus::Incomplete);
    let second = subscription("shared", "cus_user", SubscriptionStatus::Trialing);
    store.create_subscription(first.clone()).await.unwrap();
    store.create_subscription(second.clone()).await.unwrap();
    assert_eq!(
        store
            .list_subscriptions("shared")
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect::<Vec<_>>(),
        [first.id, second.id]
    );
    assert_eq!(
        store
            .find_active_subscription_by_customer("cus_user")
            .await
            .unwrap()
            .map(|row| row.id),
        Some(second.id)
    );
}

#[test]
fn complete_error_dictionary_and_debug_output_do_not_leak_secrets() {
    assert_eq!(StripeErrorCode::ALL.len(), 23);
    assert_eq!(
        StripeErrorCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>(),
        vec![
            "UNAUTHORIZED",
            "INVALID_REQUEST_BODY",
            "SUBSCRIPTION_NOT_FOUND",
            "SUBSCRIPTION_PLAN_NOT_FOUND",
            "ALREADY_SUBSCRIBED_PLAN",
            "REFERENCE_ID_NOT_ALLOWED",
            "CUSTOMER_NOT_FOUND",
            "UNABLE_TO_CREATE_CUSTOMER",
            "UNABLE_TO_CREATE_BILLING_PORTAL",
            "STRIPE_SIGNATURE_NOT_FOUND",
            "STRIPE_WEBHOOK_SECRET_NOT_FOUND",
            "STRIPE_WEBHOOK_ERROR",
            "FAILED_TO_CONSTRUCT_STRIPE_EVENT",
            "FAILED_TO_FETCH_PLANS",
            "EMAIL_VERIFICATION_REQUIRED",
            "SUBSCRIPTION_NOT_ACTIVE",
            "SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION",
            "SUBSCRIPTION_NOT_PENDING_CHANGE",
            "ORGANIZATION_NOT_FOUND",
            "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED",
            "AUTHORIZE_REFERENCE_REQUIRED",
            "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION",
            "ORGANIZATION_REFERENCE_ID_REQUIRED",
        ]
    );

    let client = Arc::new(StripeHttpClient::new("sk_live_must_not_leak"));
    let options = StripeOptions::new(client.clone(), "whsec_must_not_leak");
    let debug = format!("{options:?} {client:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("sk_live_must_not_leak"));
    assert!(!debug.contains("whsec_must_not_leak"));
}

fn plan(name: &str) -> StripePlan {
    StripePlan {
        name: name.into(),
        price_id: Some("price_monthly".into()),
        lookup_key: None,
        annual_discount_price_id: None,
        annual_discount_lookup_key: None,
        limits: None,
        group: None,
        seat_price_id: None,
        proration_behavior: Default::default(),
        line_items: Vec::new(),
        free_trial: None,
    }
}

fn subscription(reference_id: &str, customer_id: &str, status: SubscriptionStatus) -> Subscription {
    Subscription {
        id: Uuid::new_v4(),
        plan: "pro".into(),
        reference_id: reference_id.into(),
        stripe_customer_id: Some(customer_id.into()),
        stripe_subscription_id: Some(format!("sub_{}", Uuid::new_v4())),
        status,
        period_start: None,
        period_end: None,
        trial_start: None,
        trial_end: None,
        cancel_at_period_end: false,
        cancel_at: None,
        canceled_at: None,
        ended_at: None,
        seats: None,
        billing_interval: None,
        stripe_schedule_id: None,
    }
}
