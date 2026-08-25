use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargebeeProviderCustomer {
    pub id: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default, rename = "meta_data")]
    pub metadata: Option<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargebeeProviderSubscriptionItem {
    pub item_price_id: String,
    #[serde(default)]
    pub item_type: Option<String>,
    #[serde(default)]
    pub quantity: Option<f64>,
    #[serde(default)]
    pub unit_price: Option<f64>,
    #[serde(default)]
    pub amount: Option<f64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargebeeProviderSubscription {
    pub id: String,
    pub customer_id: String,
    pub status: String,
    #[serde(default)]
    pub current_term_start: Option<i64>,
    #[serde(default)]
    pub current_term_end: Option<i64>,
    #[serde(default)]
    pub trial_start: Option<i64>,
    #[serde(default)]
    pub trial_end: Option<i64>,
    #[serde(default)]
    pub cancelled_at: Option<i64>,
    #[serde(default)]
    pub subscription_items: Vec<ChargebeeProviderSubscriptionItem>,
    #[serde(default, rename = "meta_data")]
    pub metadata: Option<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChargebeeCustomerListRequest {
    pub email: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChargebeeSubscriptionListRequest {
    pub customer_id: String,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargebeeHostedPage {
    pub id: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargebeePortalSession {
    pub access_url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargebeeWebhookEvent {
    pub event_type: String,
    pub id: Value,
    #[serde(default)]
    pub content: Value,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ChargebeeWebhookEvent {
    pub fn subscription(&self) -> Option<ChargebeeProviderSubscription> {
        self.content
            .get("subscription")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
    }

    pub fn customer(&self) -> Option<ChargebeeProviderCustomer> {
        self.content
            .get("customer")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ChargebeeProviderError {
    pub message: String,
    pub api_error_code: Option<String>,
    pub kind: ChargebeeProviderErrorKind,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChargebeeProviderErrorKind {
    #[default]
    Api,
    WebhookAuthentication,
    WebhookPayload,
}

impl ChargebeeProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            api_error_code: None,
            kind: ChargebeeProviderErrorKind::Api,
        }
    }

    pub fn with_api_error_code(mut self, code: impl Into<String>) -> Self {
        self.api_error_code = Some(code.into());
        self
    }

    pub fn webhook_authentication(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            api_error_code: None,
            kind: ChargebeeProviderErrorKind::WebhookAuthentication,
        }
    }

    pub fn webhook_payload(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            api_error_code: None,
            kind: ChargebeeProviderErrorKind::WebhookPayload,
        }
    }
}

#[async_trait]
pub trait ChargebeeClient: Send + Sync {
    /// Mirrors Chargebee SDK's internal `__clientIdentifier` registration.
    fn set_client_identifier(&self, _identifier: &str) {}

    async fn list_customers(
        &self,
        request: ChargebeeCustomerListRequest,
    ) -> Result<Vec<ChargebeeProviderCustomer>, ChargebeeProviderError>;

    async fn create_customer(
        &self,
        request: Value,
    ) -> Result<ChargebeeProviderCustomer, ChargebeeProviderError>;

    async fn update_customer(
        &self,
        customer_id: &str,
        request: Value,
    ) -> Result<ChargebeeProviderCustomer, ChargebeeProviderError>;

    async fn delete_customer(&self, customer_id: &str) -> Result<(), ChargebeeProviderError>;

    async fn list_subscriptions(
        &self,
        request: ChargebeeSubscriptionListRequest,
    ) -> Result<Vec<ChargebeeProviderSubscription>, ChargebeeProviderError>;

    async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<ChargebeeProviderSubscription, ChargebeeProviderError>;

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        end_of_term: bool,
    ) -> Result<ChargebeeProviderSubscription, ChargebeeProviderError>;

    async fn checkout_new_for_items(
        &self,
        request: Value,
    ) -> Result<ChargebeeHostedPage, ChargebeeProviderError>;

    async fn checkout_existing_for_items(
        &self,
        request: Value,
    ) -> Result<ChargebeeHostedPage, ChargebeeProviderError>;

    async fn create_portal_session(
        &self,
        request: Value,
    ) -> Result<ChargebeePortalSession, ChargebeeProviderError>;

    /// Parse and authenticate a provider webhook using the injected SDK seam.
    /// Both credentials are `Some` only when the plugin configured both.
    async fn parse_webhook(
        &self,
        payload: &[u8],
        authorization: Option<&str>,
        credentials: Option<(&str, &str)>,
    ) -> Result<ChargebeeWebhookEvent, ChargebeeProviderError>;
}

#[cfg(test)]
mod tests {
    use super::ChargebeeWebhookEvent;
    use serde_json::json;

    #[test]
    fn event_ids_preserve_the_artifacts_truthy_non_string_edge() {
        let event: ChargebeeWebhookEvent = serde_json::from_value(json!({
            "event_type": "subscription_created",
            "id": 42,
            "content": {}
        }))
        .unwrap();
        assert_eq!(event.id, json!(42));
    }
}
