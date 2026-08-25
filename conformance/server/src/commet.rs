use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, CommetClient, CommetCustomerCreate, CommetCustomerUpdate, CommetFeature,
    CommetOptions, CommetPlugin, CommetPortalOptions, CommetProviderError, CommetSeatMutation,
    CommetSeatSetAll, CommetSubscriptionCancel, CommetSubscriptionsOptions, CommetUsageEvent,
    CommetWebhooksOptions,
};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Debug)]
struct ConformanceCommet;

const PORTAL_URL: &str = "https://commet.example.test/portal?keep=native";

pub(super) fn register(config: &mut AuthConfig) {
    let options = CommetOptions::new(
        Arc::new(ConformanceCommet),
        vec![
            CommetFeature::Portal(CommetPortalOptions {
                return_url: Some("https://app.example.test/billing?tab=plans".into()),
            }),
            CommetFeature::Subscriptions(CommetSubscriptionsOptions::default()),
            CommetFeature::Features,
            CommetFeature::Usage,
            CommetFeature::Seats,
            CommetFeature::Webhooks(CommetWebhooksOptions::new("commet-native-conformance")),
        ],
    );
    config
        .add_plugin(CommetPlugin::new(options))
        .expect("unique Commet plugin");
}

#[async_trait]
impl CommetClient for ConformanceCommet {
    async fn list_customers(&self, external_id: &str) -> Result<Value, CommetProviderError> {
        Ok(json!({"data": [{"externalId": external_id, "id": "customer_native"}]}))
    }

    async fn create_customer(
        &self,
        request: CommetCustomerCreate,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({"email": request.email, "id": "customer_native"}))
    }

    async fn update_customer(
        &self,
        customer_id: &str,
        _request: CommetCustomerUpdate,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({"id": customer_id}))
    }

    async fn create_portal_session(&self, customer_id: &str) -> Result<Value, CommetProviderError> {
        assert!(!customer_id.is_empty());
        Ok(json!({"portalUrl": PORTAL_URL}))
    }

    async fn get_active_subscription(
        &self,
        customer_id: &str,
    ) -> Result<Value, CommetProviderError> {
        assert!(!customer_id.is_empty());
        Ok(json!({"id": "subscription_native", "status": "active"}))
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        request: CommetSubscriptionCancel,
    ) -> Result<Value, CommetProviderError> {
        assert_eq!(subscription_id, "subscription_native");
        assert_eq!(request.reason.as_deref(), Some("native cancellation"));
        assert_eq!(request.immediate, Some(true));
        Ok(json!({
            "id": subscription_id,
            "immediate": request.immediate,
            "reason": request.reason,
            "status": "canceled",
        }))
    }

    async fn list_feature_access(&self, customer_id: &str) -> Result<Value, CommetProviderError> {
        assert!(!customer_id.is_empty());
        Ok(json!({
            "data": [{"code": "reports", "enabled": true}],
            "next": "projected-away",
        }))
    }

    async fn get_feature_access(
        &self,
        customer_id: &str,
        code: &str,
    ) -> Result<Value, CommetProviderError> {
        assert!(!customer_id.is_empty());
        assert_eq!(code, "reports");
        Ok(json!({"code": code, "enabled": true, "limit": 100}))
    }

    async fn check_usage(
        &self,
        customer_id: &str,
        feature_code: &str,
    ) -> Result<Value, CommetProviderError> {
        assert!(!customer_id.is_empty());
        assert_eq!(feature_code, "reports");
        Ok(json!({"allowed": true, "remaining": 98}))
    }

    async fn create_usage_event(
        &self,
        request: CommetUsageEvent,
        idempotency_key: Option<&str>,
    ) -> Result<Value, CommetProviderError> {
        assert!(!request.customer_id.is_empty());
        assert_eq!(request.feature_code, "reports");
        assert_eq!(request.value, Some(2.into()));
        assert_eq!(idempotency_key, Some("usage-native"));
        let properties = request.properties.expect("usage properties");
        assert_eq!(properties.len(), 2);
        assert_eq!(properties[0].property, "source");
        assert_eq!(properties[0].value, "native");
        assert_eq!(properties[1].property, "tier");
        assert_eq!(properties[1].value, "pro");
        Ok(json!({"featureCode": request.feature_code, "id": "usage_native"}))
    }

    async fn list_seat_balances(&self, customer_id: &str) -> Result<Value, CommetProviderError> {
        assert!(!customer_id.is_empty());
        Ok(json!({"balances": {"admins": 1, "members": 4}, "ignored": true}))
    }

    async fn add_seats(&self, request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        seat_result("add", request, 2.into())
    }

    async fn remove_seats(
        &self,
        request: CommetSeatMutation,
    ) -> Result<Value, CommetProviderError> {
        seat_result("remove", request, 1.into())
    }

    async fn set_seats(&self, request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        seat_result("set", request, 4.into())
    }

    async fn set_all_seats(&self, request: CommetSeatSetAll) -> Result<Value, CommetProviderError> {
        assert!(!request.customer_id.is_empty());
        assert_eq!(
            request.seats,
            serde_json::Map::from_iter(
                [("admins".into(), json!(1)), ("members".into(), json!(4)),]
            )
        );
        Ok(json!({
            "data": [
                {"featureCode": "admins", "count": 1},
                {"featureCode": "members", "count": 4},
            ]
        }))
    }
}

fn seat_result(
    operation: &'static str,
    request: CommetSeatMutation,
    expected: serde_json::Number,
) -> Result<Value, CommetProviderError> {
    assert!(!request.customer_id.is_empty());
    assert_eq!(request.feature_code, "members");
    assert_eq!(request.count, expected);
    Ok(json!({"count": request.count, "operation": operation}))
}
