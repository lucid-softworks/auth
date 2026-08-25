use super::PolarProviderError;
use crate::polar::schema::{ComponentKind, normalize_component};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolarPageItemKind {
    Customer,
    BenefitGrant,
    CustomerSubscription,
    Order,
    Meter,
    Subscription,
}

/// Response family used to apply the pinned SDK's validation and projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolarResponseKind {
    Checkout,
    Customer,
    CustomerSession,
    CustomerState,
    Page(PolarPageItemKind),
    Ingestion,
}

pub fn normalize_sdk_value(
    value: Value,
    kind: PolarResponseKind,
) -> Result<Value, PolarProviderError> {
    normalize_component(value, component_kind(kind)).map_err(|error| {
        PolarProviderError::new(format!("Polar SDK response validation failed: {error}"))
    })
}

const fn component_kind(kind: PolarResponseKind) -> ComponentKind {
    match kind {
        PolarResponseKind::Checkout => ComponentKind::Checkout,
        PolarResponseKind::Customer => ComponentKind::Customer,
        PolarResponseKind::CustomerSession => ComponentKind::CustomerSession,
        PolarResponseKind::CustomerState => ComponentKind::CustomerState,
        PolarResponseKind::Page(PolarPageItemKind::Customer) => ComponentKind::CustomerPage,
        PolarResponseKind::Page(PolarPageItemKind::BenefitGrant) => ComponentKind::BenefitGrantPage,
        PolarResponseKind::Page(PolarPageItemKind::CustomerSubscription) => {
            ComponentKind::CustomerSubscriptionPage
        }
        PolarResponseKind::Page(PolarPageItemKind::Order) => ComponentKind::OrderPage,
        PolarResponseKind::Page(PolarPageItemKind::Meter) => ComponentKind::MeterPage,
        PolarResponseKind::Page(PolarPageItemKind::Subscription) => ComponentKind::SubscriptionPage,
        PolarResponseKind::Ingestion => ComponentKind::Ingestion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn applies_sdk_defaults_and_validates_complete_shapes() {
        assert_eq!(
            normalize_sdk_value(json!({"inserted": 2}), PolarResponseKind::Ingestion).unwrap(),
            json!({"inserted":2,"duplicates":0})
        );
        assert!(
            normalize_sdk_value(json!({"id": "customer_1"}), PolarResponseKind::Customer).is_err()
        );
        assert!(
            normalize_sdk_value(
                json!({"items": [], "pagination": {"total_count": 0, "max_page": 1}}),
                PolarResponseKind::Page(PolarPageItemKind::Customer)
            )
            .is_ok()
        );
    }
}
