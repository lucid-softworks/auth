use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One persisted row from Creem's optional subscription model.
///
/// Provider status and owner references deliberately remain strings. The
/// pinned plugin accepts statuses outside a closed enum and does not require a
/// subscription reference to use the native auth store's UUID representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreemSubscription {
    pub id: Uuid,
    pub product_id: String,
    pub reference_id: String,
    pub creem_customer_id: Option<String>,
    pub creem_subscription_id: Option<String>,
    pub creem_order_id: Option<String>,
    pub status: String,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
}

impl CreemSubscription {
    pub const DEFAULT_STATUS: &'static str = "pending";

    pub fn new(product_id: impl Into<String>, reference_id: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            product_id: product_id.into(),
            reference_id: reference_id.into(),
            creem_customer_id: None,
            creem_subscription_id: None,
            creem_order_id: None,
            status: Self::DEFAULT_STATUS.into(),
            period_start: None,
            period_end: None,
            cancel_at_period_end: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_subscription_applies_adapter_defaults() {
        let subscription = CreemSubscription::new("product", "owner");
        assert_eq!(subscription.product_id, "product");
        assert_eq!(subscription.reference_id, "owner");
        assert_eq!(subscription.status, "pending");
        assert!(!subscription.cancel_at_period_end);
        assert!(subscription.creem_customer_id.is_none());
        assert!(subscription.period_end.is_none());
    }
}
