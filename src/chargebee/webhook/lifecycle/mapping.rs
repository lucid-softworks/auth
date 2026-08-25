use super::LifecycleError;
use crate::chargebee::{
    ChargebeeOptions, ChargebeePlan, ChargebeeProviderSubscriptionItem, ChargebeeSubscriptionItem,
    ChargebeeSubscriptionStatus,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

pub(super) fn status(value: &str) -> ChargebeeSubscriptionStatus {
    value
        .parse()
        .expect("Chargebee status parsing is infallible")
}

pub(super) fn timestamp(value: Option<i64>) -> Result<Option<DateTime<Utc>>, LifecycleError> {
    value
        .filter(|value| *value != 0)
        .map(|value| {
            DateTime::from_timestamp(value, 0).ok_or(LifecycleError::InvalidTimestamp(value))
        })
        .transpose()
}

pub(super) fn quantity(value: Option<f64>) -> f64 {
    value
        .filter(|value| *value != 0.0 && !value.is_nan())
        .unwrap_or(1.0)
}

pub(super) fn optional_number(value: Option<f64>) -> Option<f64> {
    value.filter(|value| *value != 0.0 && !value.is_nan())
}

pub(super) fn item(
    subscription_id: Uuid,
    provider: &ChargebeeProviderSubscriptionItem,
) -> ChargebeeSubscriptionItem {
    let item_type = provider
        .item_type
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("plan");
    let mut item = ChargebeeSubscriptionItem::new(
        subscription_id,
        provider.item_price_id.clone(),
        item_type
            .parse()
            .expect("Chargebee item-type parsing is infallible"),
        quantity(provider.quantity),
    );
    item.unit_price = optional_number(provider.unit_price);
    item.amount = optional_number(provider.amount);
    item
}

pub(super) async fn plan(
    options: &ChargebeeOptions,
    item_price_id: &str,
) -> Result<Option<ChargebeePlan>, LifecycleError> {
    Ok(options
        .plans()
        .await?
        .into_iter()
        .find(|plan| plan.item_price_id == item_price_id))
}

pub(super) fn metadata_string<'a>(metadata: Option<&'a Value>, field: &str) -> Option<&'a str> {
    metadata
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get(field))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chargebee::ChargebeeItemType;
    use std::collections::BTreeMap;

    #[test]
    fn numeric_mapping_uses_javascript_truthiness() {
        assert_eq!(quantity(None), 1.0);
        assert_eq!(quantity(Some(0.0)), 1.0);
        assert_eq!(quantity(Some(-2.5)), -2.5);
        assert_eq!(optional_number(Some(0.0)), None);
        assert_eq!(optional_number(Some(3.0)), Some(3.0));
        assert_eq!(timestamp(Some(0)).unwrap(), None);
        assert_eq!(timestamp(Some(1)).unwrap().unwrap().timestamp(), 1);
    }

    #[test]
    fn item_mapping_defaults_zero_values_like_javascript_or() {
        let subscription_id = Uuid::new_v4();
        let item = item(
            subscription_id,
            &ChargebeeProviderSubscriptionItem {
                item_price_id: "price".into(),
                item_type: Some(String::new()),
                quantity: Some(0.0),
                unit_price: Some(0.0),
                amount: Some(0.0),
                extra: BTreeMap::new(),
            },
        );
        assert_eq!(item.item_type, ChargebeeItemType::Plan);
        assert_eq!(item.quantity, 1.0);
        assert_eq!(item.unit_price, None);
        assert_eq!(item.amount, None);
    }

    #[test]
    fn provider_added_status_and_item_type_are_preserved() {
        assert_eq!(
            status("provider_added"),
            ChargebeeSubscriptionStatus::Other("provider_added".into())
        );
        let item = item(
            Uuid::new_v4(),
            &ChargebeeProviderSubscriptionItem {
                item_price_id: "price".into(),
                item_type: Some("metered".into()),
                quantity: Some(1.0),
                unit_price: None,
                amount: None,
                extra: BTreeMap::new(),
            },
        );
        assert_eq!(item.item_type, ChargebeeItemType::Other("metered".into()));
    }
}
