use crate::stripe::{BillingInterval, StripeMetadata, SubscriptionStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StripeRequestOptions {
    pub idempotency_key: Option<String>,
    pub stripe_account: Option<String>,
    pub api_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripePage<T> {
    pub data: Vec<T>,
    #[serde(default)]
    pub has_more: bool,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeCustomer {
    pub id: String,
    #[serde(default)]
    pub deleted: bool,
    pub email: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub metadata: StripeMetadata,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripePrice {
    pub id: String,
    #[serde(default)]
    pub active: bool,
    pub lookup_key: Option<String>,
    pub recurring: Option<StripeRecurring>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeRecurring {
    pub interval: BillingInterval,
    pub usage_type: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeCheckoutSession {
    pub id: String,
    pub url: Option<String>,
    pub mode: Option<String>,
    pub subscription: Option<Value>,
    pub customer: Option<Value>,
    pub payment_status: Option<String>,
    pub client_reference_id: Option<String>,
    #[serde(default)]
    pub metadata: StripeMetadata,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl StripeCheckoutSession {
    pub fn subscription_id(&self) -> Option<&str> {
        object_id(self.subscription.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    pub customer: Value,
    pub status: SubscriptionStatus,
    #[serde(default)]
    pub items: StripeSubscriptionItemList,
    pub schedule: Option<Value>,
    #[serde(default)]
    pub metadata: StripeMetadata,
    pub trial_start: Option<i64>,
    pub trial_end: Option<i64>,
    #[serde(default)]
    pub cancel_at_period_end: bool,
    pub cancel_at: Option<i64>,
    pub canceled_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub cancellation_details: Option<Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl StripeSubscription {
    pub fn customer_id(&self) -> Option<&str> {
        object_id(Some(&self.customer))
    }

    pub fn schedule_id(&self) -> Option<&str> {
        object_id(self.schedule.as_ref())
    }

    pub const fn is_active_or_trialing(&self) -> bool {
        self.status.is_active_or_trialing()
    }

    pub const fn is_pending_cancel(&self) -> bool {
        self.cancel_at_period_end || self.cancel_at.is_some()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StripeSubscriptionItemList {
    #[serde(default)]
    pub data: Vec<StripeSubscriptionItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeSubscriptionItem {
    pub id: String,
    pub price: StripePrice,
    pub quantity: Option<f64>,
    pub current_period_start: i64,
    pub current_period_end: i64,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeSubscriptionSchedule {
    pub id: String,
    pub status: String,
    pub subscription: Option<Value>,
    pub current_phase: Option<StripeSchedulePhase>,
    #[serde(default)]
    pub phases: Vec<StripeSchedulePhase>,
    #[serde(default)]
    pub metadata: StripeMetadata,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeSchedulePhase {
    pub start_date: Value,
    pub end_date: Option<Value>,
    #[serde(default)]
    pub items: Vec<StripeScheduleItem>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeScheduleItem {
    pub price: Value,
    pub quantity: Option<f64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeBillingPortalSession {
    pub id: String,
    pub url: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeEventData {
    pub object: Value,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct StripeProviderError {
    pub code: Option<String>,
    pub message: String,
    pub status: Option<u16>,
}

impl StripeProviderError {
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            code: None,
            message: message.into(),
            status: None,
        }
    }
}

fn object_id(value: Option<&Value>) -> Option<&str> {
    match value? {
        Value::String(id) => Some(id),
        Value::Object(object) => object.get("id").and_then(Value::as_str),
        _ => None,
    }
}
