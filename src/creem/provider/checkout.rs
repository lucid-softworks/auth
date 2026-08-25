use super::{
    commerce::{
        CustomerOrId, DiscountEntity, EnvironmentMode, Nullable, OrderEntity, ProductOrId,
        ResponseCustomField,
    },
    features::{LicenseEntity, ProductFeatureEntity},
    subscription::SubscriptionEntity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckoutStatus {
    Pending,
    Processing,
    Completed,
    Expired,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum SubscriptionOrId {
    Subscription(Box<SubscriptionEntity>),
    Id(String),
}

impl SubscriptionOrId {
    fn validate(&self) -> Result<(), ()> {
        match self {
            Self::Subscription(subscription) => subscription.validate(),
            Self::Id(_) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckoutEntity {
    id: String,
    mode: EnvironmentMode,
    object: String,
    status: CheckoutStatus,
    #[serde(
        rename(deserialize = "request_id", serialize = "requestId"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    request_id: Option<String>,
    product: ProductOrId,
    #[serde(default = "one")]
    units: f64,
    #[serde(
        rename(deserialize = "custom_price", serialize = "customPrice"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    custom_price: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    order: Option<OrderEntity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subscription: Option<SubscriptionOrId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    customer: Option<CustomerOrId>,
    #[serde(
        rename(deserialize = "custom_fields", serialize = "customFields"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    custom_fields: Option<Vec<ResponseCustomField>>,
    #[serde(
        rename(deserialize = "checkout_url", serialize = "checkoutUrl"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    checkout_url: Option<String>,
    #[serde(
        rename(deserialize = "success_url", serialize = "successUrl"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    success_url: Nullable<String>,
    #[serde(
        rename(deserialize = "license_keys", serialize = "licenseKeys"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    license_keys: Option<Vec<LicenseEntity>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    feature: Option<Vec<ProductFeatureEntity>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discount: Option<DiscountEntity>,
}

const fn one() -> f64 {
    1.0
}

pub(crate) fn normalize_checkout(value: Value) -> Result<(Option<String>, Value), ()> {
    let parsed: CheckoutEntity = serde_json::from_value(value).map_err(|_| ())?;
    if let Some(customer) = &parsed.customer {
        customer.validate()?;
    }
    if let Some(subscription) = &parsed.subscription {
        subscription.validate()?;
    }
    if parsed
        .custom_price
        .is_some_and(|value| value.fract() != 0.0)
    {
        return Err(());
    }
    let checkout_url = parsed.checkout_url.clone();
    serde_json::to_value(parsed)
        .map(|value| (checkout_url, value))
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checkout_defaults_units_remaps_and_strips_unknown_fields() {
        let (url, normalized) = normalize_checkout(json!({
            "id": "checkout_1",
            "mode": "test",
            "object": "checkout",
            "status": "pending",
            "request_id": "request_1",
            "product": "product_1",
            "checkout_url": "https://checkout.test/1",
            "unknown": "stripped"
        }))
        .unwrap();
        assert_eq!(url.as_deref(), Some("https://checkout.test/1"));
        assert_eq!(
            normalized,
            json!({
                "id": "checkout_1",
                "mode": "test",
                "object": "checkout",
                "status": "pending",
                "requestId": "request_1",
                "product": "product_1",
                "units": 1.0,
                "checkoutUrl": "https://checkout.test/1"
            })
        );
    }

    #[test]
    fn checkout_url_is_optional_but_required_fields_are_not() {
        let (url, value) = normalize_checkout(json!({
            "id": "checkout_1",
            "mode": "prod",
            "object": "checkout",
            "status": "completed",
            "product": "product_1"
        }))
        .unwrap();
        assert_eq!(url, None);
        assert_eq!(value["units"], 1.0);
        assert!(normalize_checkout(json!({"id": "checkout_1"})).is_err());
    }

    #[test]
    fn nullable_values_and_embedded_discount_names_match_sdk_output() {
        let (_, value) = normalize_checkout(json!({
            "id": "checkout_1",
            "mode": "test",
            "object": "checkout",
            "status": "pending",
            "product": "product_1",
            "customer": {
                "id": "customer_1",
                "mode": "test",
                "object": "customer",
                "email": "user@example.com",
                "country": null,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            },
            "success_url": null,
            "discount": {
                "discountCode": "SAVE",
                "durationInMonths": 3
            }
        }))
        .unwrap();
        assert_eq!(value["customer"]["country"], Value::Null);
        assert_eq!(value["successUrl"], Value::Null);
        assert_eq!(value["discount"]["discountCode"], "SAVE");
        assert_eq!(value["discount"]["durationInMonths"], 3.0);
    }
}
