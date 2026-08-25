use super::PolarWebhookError;
use crate::polar::schema::normalize_webhook;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolarWebhookEventType {
    #[serde(rename = "checkout.created")]
    CheckoutCreated,
    #[serde(rename = "checkout.updated")]
    CheckoutUpdated,
    #[serde(rename = "checkout.expired")]
    CheckoutExpired,
    #[serde(rename = "order.created")]
    OrderCreated,
    #[serde(rename = "order.updated")]
    OrderUpdated,
    #[serde(rename = "order.paid")]
    OrderPaid,
    #[serde(rename = "order.refunded")]
    OrderRefunded,
    #[serde(rename = "refund.created")]
    RefundCreated,
    #[serde(rename = "refund.updated")]
    RefundUpdated,
    #[serde(rename = "subscription.created")]
    SubscriptionCreated,
    #[serde(rename = "subscription.updated")]
    SubscriptionUpdated,
    #[serde(rename = "subscription.active")]
    SubscriptionActive,
    #[serde(rename = "subscription.canceled")]
    SubscriptionCanceled,
    #[serde(rename = "subscription.uncanceled")]
    SubscriptionUncanceled,
    #[serde(rename = "subscription.revoked")]
    SubscriptionRevoked,
    #[serde(rename = "subscription.past_due")]
    SubscriptionPastDue,
    #[serde(rename = "product.created")]
    ProductCreated,
    #[serde(rename = "product.updated")]
    ProductUpdated,
    #[serde(rename = "organization.updated")]
    OrganizationUpdated,
    #[serde(rename = "benefit.created")]
    BenefitCreated,
    #[serde(rename = "benefit.updated")]
    BenefitUpdated,
    #[serde(rename = "benefit_grant.created")]
    BenefitGrantCreated,
    #[serde(rename = "benefit_grant.updated")]
    BenefitGrantUpdated,
    #[serde(rename = "benefit_grant.revoked")]
    BenefitGrantRevoked,
    #[serde(rename = "benefit_grant.cycled")]
    BenefitGrantCycled,
    #[serde(rename = "customer.created")]
    CustomerCreated,
    #[serde(rename = "customer.updated")]
    CustomerUpdated,
    #[serde(rename = "customer.deleted")]
    CustomerDeleted,
    #[serde(rename = "customer.state_changed")]
    CustomerStateChanged,
    #[serde(rename = "customer_seat.assigned")]
    CustomerSeatAssigned,
    #[serde(rename = "customer_seat.claimed")]
    CustomerSeatClaimed,
    #[serde(rename = "customer_seat.revoked")]
    CustomerSeatRevoked,
    #[serde(rename = "member.created")]
    MemberCreated,
    #[serde(rename = "member.updated")]
    MemberUpdated,
    #[serde(rename = "member.deleted")]
    MemberDeleted,
}

impl PolarWebhookEventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CheckoutCreated => "checkout.created",
            Self::CheckoutUpdated => "checkout.updated",
            Self::CheckoutExpired => "checkout.expired",
            Self::OrderCreated => "order.created",
            Self::OrderUpdated => "order.updated",
            Self::OrderPaid => "order.paid",
            Self::OrderRefunded => "order.refunded",
            Self::RefundCreated => "refund.created",
            Self::RefundUpdated => "refund.updated",
            Self::SubscriptionCreated => "subscription.created",
            Self::SubscriptionUpdated => "subscription.updated",
            Self::SubscriptionActive => "subscription.active",
            Self::SubscriptionCanceled => "subscription.canceled",
            Self::SubscriptionUncanceled => "subscription.uncanceled",
            Self::SubscriptionRevoked => "subscription.revoked",
            Self::SubscriptionPastDue => "subscription.past_due",
            Self::ProductCreated => "product.created",
            Self::ProductUpdated => "product.updated",
            Self::OrganizationUpdated => "organization.updated",
            Self::BenefitCreated => "benefit.created",
            Self::BenefitUpdated => "benefit.updated",
            Self::BenefitGrantCreated => "benefit_grant.created",
            Self::BenefitGrantUpdated => "benefit_grant.updated",
            Self::BenefitGrantRevoked => "benefit_grant.revoked",
            Self::BenefitGrantCycled => "benefit_grant.cycled",
            Self::CustomerCreated => "customer.created",
            Self::CustomerUpdated => "customer.updated",
            Self::CustomerDeleted => "customer.deleted",
            Self::CustomerStateChanged => "customer.state_changed",
            Self::CustomerSeatAssigned => "customer_seat.assigned",
            Self::CustomerSeatClaimed => "customer_seat.claimed",
            Self::CustomerSeatRevoked => "customer_seat.revoked",
            Self::MemberCreated => "member.created",
            Self::MemberUpdated => "member.updated",
            Self::MemberDeleted => "member.deleted",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolarWebhookEvent {
    pub event_type: PolarWebhookEventType,
    /// Complete SDK-normalized event value received by callbacks.
    pub value: Value,
}

impl PolarWebhookEvent {
    pub(crate) fn parse(value: Value) -> Result<Self, PolarWebhookError> {
        let event_type = value
            .get("type")
            .and_then(Value::as_str)
            .ok_or(PolarWebhookError::InvalidPayload)?;
        let event_type: PolarWebhookEventType =
            serde_json::from_value(Value::String(event_type.into()))
                .map_err(|_| PolarWebhookError::UnsupportedEvent)?;
        let (_, value) = normalize_webhook(value).map_err(|_| PolarWebhookError::InvalidPayload)?;
        Ok(Self { event_type, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recognizes_and_projects_sdk_only_events() {
        let event = PolarWebhookEvent::parse(json!({
            "type": "member.created",
            "timestamp": "2025-01-01T00:00:00Z",
            "data": {
                "id": "member_1",
                "created_at": "2025-01-01T00:00:00Z",
                "modified_at": null,
                "customer_id": "customer_1",
                "email": "member@example.com",
                "name": null,
                "external_id": null,
                "role": "member",
                "provider_only": true
            }
        }))
        .unwrap();
        assert_eq!(event.event_type, PolarWebhookEventType::MemberCreated);
        assert_eq!(event.value["data"]["createdAt"], "2025-01-01T00:00:00.000Z");
        assert_eq!(event.value["data"]["customerId"], "customer_1");
        assert!(event.value["data"].get("providerOnly").is_none());
        assert_eq!(
            PolarWebhookEvent::parse(json!({
                "type":"future.event",
                "timestamp":"2025-01-01T00:00:00Z",
                "data":{}
            })),
            Err(PolarWebhookError::UnsupportedEvent)
        );
    }
}
