use super::{
    commerce::{CustomerOrId, DiscountEntity, EnvironmentMode, Nullable, ProductOrId, SdkDate},
    transaction::TransactionEntity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
enum CollectionMethod {
    #[serde(rename = "charge_automatically")]
    ChargeAutomatically,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) enum SubscriptionStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "canceled")]
    Canceled,
    #[serde(rename = "unpaid")]
    Unpaid,
    #[serde(rename = "paused")]
    Paused,
    #[serde(rename = "trialing")]
    Trialing,
    #[serde(rename = "scheduled_cancel")]
    ScheduledCancel,
    #[serde(rename = "past_due")]
    PastDue,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionItem {
    id: String,
    mode: EnvironmentMode,
    object: String,
    #[serde(
        rename(deserialize = "product_id", serialize = "productId"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    product_id: Option<String>,
    #[serde(
        rename(deserialize = "price_id", serialize = "priceId"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    price_id: Option<String>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    units: Nullable<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SubscriptionEntity {
    id: String,
    mode: EnvironmentMode,
    object: String,
    product: ProductOrId,
    customer: CustomerOrId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    items: Option<Vec<SubscriptionItem>>,
    #[serde(rename(deserialize = "collection_method", serialize = "collectionMethod"))]
    collection_method: CollectionMethod,
    status: SubscriptionStatus,
    #[serde(
        rename(deserialize = "last_transaction_id", serialize = "lastTransactionId"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    last_transaction_id: Option<String>,
    #[serde(
        rename(deserialize = "last_transaction", serialize = "lastTransaction"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    last_transaction: Option<TransactionEntity>,
    #[serde(
        rename(
            deserialize = "last_transaction_date",
            serialize = "lastTransactionDate"
        ),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    last_transaction_date: Option<SdkDate>,
    #[serde(
        rename(
            deserialize = "next_transaction_date",
            serialize = "nextTransactionDate"
        ),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    next_transaction_date: Option<SdkDate>,
    #[serde(
        rename(
            deserialize = "current_period_start_date",
            serialize = "currentPeriodStartDate"
        ),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    current_period_start_date: Option<SdkDate>,
    #[serde(
        rename(
            deserialize = "current_period_end_date",
            serialize = "currentPeriodEndDate"
        ),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    current_period_end_date: Option<SdkDate>,
    #[serde(
        rename(deserialize = "canceled_at", serialize = "canceledAt"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    canceled_at: Nullable<SdkDate>,
    #[serde(rename(deserialize = "created_at", serialize = "createdAt"))]
    created_at: SdkDate,
    #[serde(rename(deserialize = "updated_at", serialize = "updatedAt"))]
    updated_at: SdkDate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discount: Option<DiscountEntity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Map<String, Value>>,
}

impl SubscriptionEntity {
    pub(super) fn validate(&self) -> Result<(), ()> {
        self.customer.validate()
    }
}

pub(crate) fn normalize_subscription(value: Value) -> Result<Value, ()> {
    let parsed: SubscriptionEntity = serde_json::from_value(value).map_err(|_| ())?;
    parsed.validate()?;
    serde_json::to_value(parsed).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn subscription_remaps_dates_and_strips_unknown_fields() {
        let normalized = normalize_subscription(json!({
            "id": "subscription_1",
            "mode": "test",
            "object": "subscription",
            "product": "product_1",
            "customer": "customer_1",
            "collection_method": "charge_automatically",
            "status": "active",
            "current_period_start_date": "2026-08-01T01:00:00+01:00",
            "created_at": "2026-07-01T00:00:00Z",
            "updated_at": "2026-08-01T00:00:00Z",
            "unknown": true
        }))
        .unwrap();
        assert_eq!(normalized["collectionMethod"], "charge_automatically");
        assert_eq!(
            normalized["currentPeriodStartDate"],
            "2026-08-01T00:00:00.000Z"
        );
        assert_eq!(normalized["createdAt"], "2026-07-01T00:00:00.000Z");
        assert!(normalized.get("unknown").is_none());
    }

    #[test]
    fn subscription_rejects_unknown_sdk_statuses() {
        assert!(
            normalize_subscription(json!({
                "id": "subscription_1",
                "mode": "test",
                "object": "subscription",
                "product": "product_1",
                "customer": "customer_1",
                "collection_method": "charge_automatically",
                "status": "expired",
                "created_at": "2026-07-01T00:00:00Z",
                "updated_at": "2026-08-01T00:00:00Z"
            }))
            .is_err()
        );
    }
}
