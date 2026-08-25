use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, ChargebeeClient, ChargebeeCustomerListRequest, ChargebeeHostedPage,
    ChargebeeOptions, ChargebeePlan, ChargebeePlanType, ChargebeePlugin, ChargebeePortalSession,
    ChargebeeProviderCustomer, ChargebeeProviderError, ChargebeeProviderSubscription,
    ChargebeeSubscriptionListRequest, ChargebeeSubscriptionOptions, ChargebeeWebhookEvent,
    MemoryChargebeeStore, MemoryStore, StaticChargebeePlans,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug)]
struct ConformanceChargebee;

pub(super) fn register(config: &mut AuthConfig, auth_store: Arc<MemoryStore>) {
    let mut options = ChargebeeOptions::new(Arc::new(ConformanceChargebee));
    options.subscription = Some(ChargebeeSubscriptionOptions::new(
        true,
        Arc::new(StaticChargebeePlans(vec![ChargebeePlan {
            name: "Native".into(),
            item_price_id: "native-USD-Monthly".into(),
            item_id: Some("native".into()),
            item_family_id: Some("native-family".into()),
            plan_type: ChargebeePlanType::Plan,
            billing_cycles: None,
            free_trial: None,
            limits: Some(json!({"projects": 7})),
        }])),
    ));
    let store = Arc::new(MemoryChargebeeStore::new(auth_store));
    config
        .add_plugin(ChargebeePlugin::new(options, store))
        .expect("unique Chargebee plugin");
}

#[async_trait]
impl ChargebeeClient for ConformanceChargebee {
    async fn list_customers(
        &self,
        _request: ChargebeeCustomerListRequest,
    ) -> Result<Vec<ChargebeeProviderCustomer>, ChargebeeProviderError> {
        Ok(Vec::new())
    }

    async fn create_customer(
        &self,
        request: Value,
    ) -> Result<ChargebeeProviderCustomer, ChargebeeProviderError> {
        Ok(ChargebeeProviderCustomer {
            id: "customer_native".into(),
            email: request
                .get("email")
                .and_then(Value::as_str)
                .map(str::to_owned),
            metadata: request.get("meta_data").cloned(),
            extra: BTreeMap::new(),
        })
    }

    async fn update_customer(
        &self,
        customer_id: &str,
        request: Value,
    ) -> Result<ChargebeeProviderCustomer, ChargebeeProviderError> {
        Ok(ChargebeeProviderCustomer {
            id: customer_id.into(),
            email: None,
            metadata: request.get("meta_data").cloned(),
            extra: BTreeMap::new(),
        })
    }

    async fn delete_customer(&self, _customer_id: &str) -> Result<(), ChargebeeProviderError> {
        Ok(())
    }

    async fn list_subscriptions(
        &self,
        _request: ChargebeeSubscriptionListRequest,
    ) -> Result<Vec<ChargebeeProviderSubscription>, ChargebeeProviderError> {
        Ok(Vec::new())
    }

    async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<ChargebeeProviderSubscription, ChargebeeProviderError> {
        Err(ChargebeeProviderError::new(format!(
            "subscription {subscription_id} is not seeded"
        )))
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        _end_of_term: bool,
    ) -> Result<ChargebeeProviderSubscription, ChargebeeProviderError> {
        self.retrieve_subscription(subscription_id).await
    }

    async fn checkout_new_for_items(
        &self,
        request: Value,
    ) -> Result<ChargebeeHostedPage, ChargebeeProviderError> {
        assert_eq!(request["customer"]["id"], "customer_native");
        assert_eq!(
            request["subscription_items"][0]["item_price_id"],
            "native-USD-Monthly"
        );
        Ok(ChargebeeHostedPage {
            id: Some("hosted_page_native".into()),
            url: Some("https://chargebee.example.test/checkout/native".into()),
        })
    }

    async fn checkout_existing_for_items(
        &self,
        _request: Value,
    ) -> Result<ChargebeeHostedPage, ChargebeeProviderError> {
        Ok(ChargebeeHostedPage {
            id: Some("hosted_page_update_native".into()),
            url: Some("https://chargebee.example.test/checkout/update-native".into()),
        })
    }

    async fn create_portal_session(
        &self,
        request: Value,
    ) -> Result<ChargebeePortalSession, ChargebeeProviderError> {
        assert_eq!(request["customer"]["id"], "customer_native");
        Ok(ChargebeePortalSession {
            access_url: "https://chargebee.example.test/portal/native".into(),
        })
    }

    async fn parse_webhook(
        &self,
        payload: &[u8],
        _authorization: Option<&str>,
        _credentials: Option<(&str, &str)>,
    ) -> Result<ChargebeeWebhookEvent, ChargebeeProviderError> {
        serde_json::from_slice(payload)
            .map_err(|error| ChargebeeProviderError::new(error.to_string()))
    }
}
