use async_trait::async_trait;
use serde_json::Value;
use std::{collections::BTreeMap, fmt, future::Future, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DodoWebhookCallbackError {
    message: String,
}

impl DodoWebhookCallbackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoWebhookEvent {
    pub event_type: DodoWebhookEventType,
    pub payload: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DodoWebhookEventType {
    PaymentSucceeded,
    PaymentFailed,
    PaymentProcessing,
    PaymentCancelled,
    RefundSucceeded,
    RefundFailed,
    DisputeOpened,
    DisputeExpired,
    DisputeAccepted,
    DisputeCancelled,
    DisputeChallenged,
    DisputeWon,
    DisputeLost,
    SubscriptionActive,
    SubscriptionOnHold,
    SubscriptionRenewed,
    SubscriptionPlanChanged,
    SubscriptionCancelled,
    SubscriptionFailed,
    SubscriptionExpired,
    SubscriptionUpdated,
    SubscriptionPaused,
    SubscriptionUnpaused,
    SubscriptionUpdatePaymentMethod,
    LicenseKeyCreated,
    AbandonedCheckoutDetected,
    AbandonedCheckoutRecovered,
    DunningStarted,
    DunningRecovered,
    CreditAdded,
    CreditDeducted,
    CreditExpired,
    CreditRolledOver,
    CreditRolloverForfeited,
    CreditOverageCharged,
    CreditOverageReset,
    CreditManualAdjustment,
    CreditBalanceLow,
    EntitlementGrantCreated,
    EntitlementGrantDelivered,
    EntitlementGrantFailed,
    EntitlementGrantRevoked,
    PayoutCreated,
    PayoutOnHold,
    PayoutInProgress,
    PayoutFailed,
    PayoutSuccess,
    Unknown,
}

impl DodoWebhookEventType {
    pub fn parse(value: &str) -> Self {
        match value {
            "payment.succeeded" => Self::PaymentSucceeded,
            "payment.failed" => Self::PaymentFailed,
            "payment.processing" => Self::PaymentProcessing,
            "payment.cancelled" => Self::PaymentCancelled,
            "refund.succeeded" => Self::RefundSucceeded,
            "refund.failed" => Self::RefundFailed,
            "dispute.opened" => Self::DisputeOpened,
            "dispute.expired" => Self::DisputeExpired,
            "dispute.accepted" => Self::DisputeAccepted,
            "dispute.cancelled" => Self::DisputeCancelled,
            "dispute.challenged" => Self::DisputeChallenged,
            "dispute.won" => Self::DisputeWon,
            "dispute.lost" => Self::DisputeLost,
            "subscription.active" => Self::SubscriptionActive,
            "subscription.on_hold" => Self::SubscriptionOnHold,
            "subscription.renewed" => Self::SubscriptionRenewed,
            "subscription.plan_changed" => Self::SubscriptionPlanChanged,
            "subscription.cancelled" => Self::SubscriptionCancelled,
            "subscription.failed" => Self::SubscriptionFailed,
            "subscription.expired" => Self::SubscriptionExpired,
            "subscription.updated" => Self::SubscriptionUpdated,
            "subscription.paused" => Self::SubscriptionPaused,
            "subscription.unpaused" => Self::SubscriptionUnpaused,
            "subscription.update_payment_method" => Self::SubscriptionUpdatePaymentMethod,
            "license_key.created" => Self::LicenseKeyCreated,
            "abandoned_checkout.detected" => Self::AbandonedCheckoutDetected,
            "abandoned_checkout.recovered" => Self::AbandonedCheckoutRecovered,
            "dunning.started" => Self::DunningStarted,
            "dunning.recovered" => Self::DunningRecovered,
            "credit.added" => Self::CreditAdded,
            "credit.deducted" => Self::CreditDeducted,
            "credit.expired" => Self::CreditExpired,
            "credit.rolled_over" => Self::CreditRolledOver,
            "credit.rollover_forfeited" => Self::CreditRolloverForfeited,
            "credit.overage_charged" => Self::CreditOverageCharged,
            "credit.overage_reset" => Self::CreditOverageReset,
            "credit.manual_adjustment" => Self::CreditManualAdjustment,
            "credit.balance_low" => Self::CreditBalanceLow,
            "entitlement_grant.created" => Self::EntitlementGrantCreated,
            "entitlement_grant.delivered" => Self::EntitlementGrantDelivered,
            "entitlement_grant.failed" => Self::EntitlementGrantFailed,
            "entitlement_grant.revoked" => Self::EntitlementGrantRevoked,
            "payout.created" => Self::PayoutCreated,
            "payout.on_hold" => Self::PayoutOnHold,
            "payout.in_progress" => Self::PayoutInProgress,
            "payout.failed" => Self::PayoutFailed,
            "payout.success" => Self::PayoutSuccess,
            _ => Self::Unknown,
        }
    }
}

#[async_trait]
pub trait DodoWebhookCallback: Send + Sync {
    async fn call(&self, event: &DodoWebhookEvent) -> Result<(), DodoWebhookCallbackError>;
}

pub struct FnDodoWebhookCallback<F>(F);

impl<F> FnDodoWebhookCallback<F> {
    pub fn new(callback: F) -> Self {
        Self(callback)
    }
}

impl<F> fmt::Debug for FnDodoWebhookCallback<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FnDodoWebhookCallback(..)")
    }
}

#[async_trait]
impl<F, Fut> DodoWebhookCallback for FnDodoWebhookCallback<F>
where
    F: Fn(DodoWebhookEvent) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), DodoWebhookCallbackError>> + Send,
{
    async fn call(&self, event: &DodoWebhookEvent) -> Result<(), DodoWebhookCallbackError> {
        (self.0)(event.clone()).await
    }
}

pub type SharedDodoWebhookCallback = Arc<dyn DodoWebhookCallback>;

#[derive(Clone, Default)]
pub struct DodoWebhookCallbacks {
    pub on_payload: Option<SharedDodoWebhookCallback>,
    named: BTreeMap<DodoWebhookEventType, SharedDodoWebhookCallback>,
}

impl DodoWebhookCallbacks {
    pub fn on(
        mut self,
        event_type: DodoWebhookEventType,
        callback: SharedDodoWebhookCallback,
    ) -> Self {
        if event_type != DodoWebhookEventType::Unknown {
            self.named.insert(event_type, callback);
        }
        self
    }

    pub fn set(&mut self, event_type: DodoWebhookEventType, callback: SharedDodoWebhookCallback) {
        if event_type != DodoWebhookEventType::Unknown {
            self.named.insert(event_type, callback);
        }
    }

    pub async fn dispatch(&self, event: &DodoWebhookEvent) -> Result<(), DodoWebhookCallbackError> {
        if let Some(callback) = &self.on_payload {
            callback.call(event).await?;
        }
        if let Some(callback) = self.named.get(&event.event_type) {
            callback.call(event).await?;
        }
        Ok(())
    }
}

impl fmt::Debug for DodoWebhookCallbacks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DodoWebhookCallbacks")
            .field("on_payload", &self.on_payload.is_some())
            .field("named_callback_count", &self.named.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Count(Arc<AtomicUsize>, usize);

    #[async_trait]
    impl DodoWebhookCallback for Count {
        async fn call(&self, _event: &DodoWebhookEvent) -> Result<(), DodoWebhookCallbackError> {
            assert_eq!(self.0.fetch_add(1, Ordering::SeqCst), self.1);
            Ok(())
        }
    }

    #[tokio::test]
    async fn generic_then_named_callbacks_are_sequential() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callbacks = DodoWebhookCallbacks {
            on_payload: Some(Arc::new(Count(calls.clone(), 0))),
            ..DodoWebhookCallbacks::default()
        }
        .on(
            DodoWebhookEventType::PaymentSucceeded,
            Arc::new(Count(calls.clone(), 1)),
        );
        callbacks
            .dispatch(&DodoWebhookEvent {
                event_type: DodoWebhookEventType::PaymentSucceeded,
                payload: serde_json::json!({"type": "payment.succeeded"}),
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unknown_events_reach_only_the_generic_callback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callbacks = DodoWebhookCallbacks {
            on_payload: Some(Arc::new(Count(calls.clone(), 0))),
            ..DodoWebhookCallbacks::default()
        };
        callbacks
            .dispatch(&DodoWebhookEvent {
                event_type: DodoWebhookEventType::Unknown,
                payload: serde_json::json!({"type": "future.event"}),
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
