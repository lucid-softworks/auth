use super::{PolarWebhookCallbackError, PolarWebhookEvent, PolarWebhookEventType};
use async_trait::async_trait;
use std::{sync::Arc, task::Poll};

#[async_trait]
pub trait PolarWebhookCallback: Send + Sync {
    async fn call(&self, event: &PolarWebhookEvent) -> Result<(), PolarWebhookCallbackError>;
}

pub type SharedPolarWebhookCallback = Arc<dyn PolarWebhookCallback>;

#[derive(Clone, Default)]
pub struct PolarWebhookCallbacks {
    pub on_payload: Option<SharedPolarWebhookCallback>,
    pub on_checkout_created: Option<SharedPolarWebhookCallback>,
    pub on_checkout_updated: Option<SharedPolarWebhookCallback>,
    pub on_order_created: Option<SharedPolarWebhookCallback>,
    pub on_order_updated: Option<SharedPolarWebhookCallback>,
    pub on_order_paid: Option<SharedPolarWebhookCallback>,
    pub on_order_refunded: Option<SharedPolarWebhookCallback>,
    pub on_refund_created: Option<SharedPolarWebhookCallback>,
    pub on_refund_updated: Option<SharedPolarWebhookCallback>,
    pub on_subscription_created: Option<SharedPolarWebhookCallback>,
    pub on_subscription_updated: Option<SharedPolarWebhookCallback>,
    pub on_subscription_active: Option<SharedPolarWebhookCallback>,
    pub on_subscription_canceled: Option<SharedPolarWebhookCallback>,
    pub on_subscription_uncanceled: Option<SharedPolarWebhookCallback>,
    pub on_subscription_revoked: Option<SharedPolarWebhookCallback>,
    pub on_product_created: Option<SharedPolarWebhookCallback>,
    pub on_product_updated: Option<SharedPolarWebhookCallback>,
    pub on_organization_updated: Option<SharedPolarWebhookCallback>,
    pub on_benefit_created: Option<SharedPolarWebhookCallback>,
    pub on_benefit_updated: Option<SharedPolarWebhookCallback>,
    pub on_benefit_grant_created: Option<SharedPolarWebhookCallback>,
    pub on_benefit_grant_updated: Option<SharedPolarWebhookCallback>,
    pub on_benefit_grant_revoked: Option<SharedPolarWebhookCallback>,
    pub on_customer_created: Option<SharedPolarWebhookCallback>,
    pub on_customer_updated: Option<SharedPolarWebhookCallback>,
    pub on_customer_deleted: Option<SharedPolarWebhookCallback>,
    pub on_customer_state_changed: Option<SharedPolarWebhookCallback>,
}

impl PolarWebhookCallbacks {
    /// Dispatches the generic and matching named callbacks concurrently, as
    /// `Promise.all` does in the pinned adapter utility.
    pub async fn dispatch(
        &self,
        event: &PolarWebhookEvent,
    ) -> Result<(), PolarWebhookCallbackError> {
        let named = self.named(event.event_type);
        match (self.on_payload.as_ref(), named) {
            (Some(payload), Some(named)) => concurrently(payload, named, event).await,
            (Some(callback), None) | (None, Some(callback)) => callback.call(event).await,
            (None, None) => Ok(()),
        }
    }

    fn named(&self, event_type: PolarWebhookEventType) -> Option<&SharedPolarWebhookCallback> {
        match event_type {
            PolarWebhookEventType::CheckoutCreated => self.on_checkout_created.as_ref(),
            PolarWebhookEventType::CheckoutUpdated => self.on_checkout_updated.as_ref(),
            PolarWebhookEventType::OrderCreated => self.on_order_created.as_ref(),
            PolarWebhookEventType::OrderUpdated => self.on_order_updated.as_ref(),
            PolarWebhookEventType::OrderPaid => self.on_order_paid.as_ref(),
            PolarWebhookEventType::OrderRefunded => self.on_order_refunded.as_ref(),
            PolarWebhookEventType::RefundCreated => self.on_refund_created.as_ref(),
            PolarWebhookEventType::RefundUpdated => self.on_refund_updated.as_ref(),
            PolarWebhookEventType::SubscriptionCreated => self.on_subscription_created.as_ref(),
            PolarWebhookEventType::SubscriptionUpdated => self.on_subscription_updated.as_ref(),
            PolarWebhookEventType::SubscriptionActive => self.on_subscription_active.as_ref(),
            PolarWebhookEventType::SubscriptionCanceled => self.on_subscription_canceled.as_ref(),
            PolarWebhookEventType::SubscriptionUncanceled => {
                self.on_subscription_uncanceled.as_ref()
            }
            PolarWebhookEventType::SubscriptionRevoked => self.on_subscription_revoked.as_ref(),
            PolarWebhookEventType::ProductCreated => self.on_product_created.as_ref(),
            PolarWebhookEventType::ProductUpdated => self.on_product_updated.as_ref(),
            PolarWebhookEventType::OrganizationUpdated => self.on_organization_updated.as_ref(),
            PolarWebhookEventType::BenefitCreated => self.on_benefit_created.as_ref(),
            PolarWebhookEventType::BenefitUpdated => self.on_benefit_updated.as_ref(),
            PolarWebhookEventType::BenefitGrantCreated => self.on_benefit_grant_created.as_ref(),
            PolarWebhookEventType::BenefitGrantUpdated => self.on_benefit_grant_updated.as_ref(),
            PolarWebhookEventType::BenefitGrantRevoked => self.on_benefit_grant_revoked.as_ref(),
            PolarWebhookEventType::CustomerCreated => self.on_customer_created.as_ref(),
            PolarWebhookEventType::CustomerUpdated => self.on_customer_updated.as_ref(),
            PolarWebhookEventType::CustomerDeleted => self.on_customer_deleted.as_ref(),
            PolarWebhookEventType::CustomerStateChanged => self.on_customer_state_changed.as_ref(),
            PolarWebhookEventType::CheckoutExpired
            | PolarWebhookEventType::SubscriptionPastDue
            | PolarWebhookEventType::BenefitGrantCycled
            | PolarWebhookEventType::CustomerSeatAssigned
            | PolarWebhookEventType::CustomerSeatClaimed
            | PolarWebhookEventType::CustomerSeatRevoked
            | PolarWebhookEventType::MemberCreated
            | PolarWebhookEventType::MemberUpdated
            | PolarWebhookEventType::MemberDeleted => None,
        }
    }
}

impl std::fmt::Debug for PolarWebhookCallbacks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolarWebhookCallbacks")
            .field("on_payload", &self.on_payload.is_some())
            .field("named_callback_count", &self.named_callback_count())
            .finish()
    }
}

impl PolarWebhookCallbacks {
    fn named_callback_count(&self) -> usize {
        [
            &self.on_checkout_created,
            &self.on_checkout_updated,
            &self.on_order_created,
            &self.on_order_updated,
            &self.on_order_paid,
            &self.on_order_refunded,
            &self.on_refund_created,
            &self.on_refund_updated,
            &self.on_subscription_created,
            &self.on_subscription_updated,
            &self.on_subscription_active,
            &self.on_subscription_canceled,
            &self.on_subscription_uncanceled,
            &self.on_subscription_revoked,
            &self.on_product_created,
            &self.on_product_updated,
            &self.on_organization_updated,
            &self.on_benefit_created,
            &self.on_benefit_updated,
            &self.on_benefit_grant_created,
            &self.on_benefit_grant_updated,
            &self.on_benefit_grant_revoked,
            &self.on_customer_created,
            &self.on_customer_updated,
            &self.on_customer_deleted,
            &self.on_customer_state_changed,
        ]
        .into_iter()
        .filter(|callback| callback.is_some())
        .count()
    }
}

async fn concurrently(
    first: &SharedPolarWebhookCallback,
    second: &SharedPolarWebhookCallback,
    event: &PolarWebhookEvent,
) -> Result<(), PolarWebhookCallbackError> {
    let mut first = first.call(event);
    let mut second = second.call(event);
    let mut first_result = None;
    let mut second_result = None;
    std::future::poll_fn(|context| {
        if first_result.is_none()
            && let Poll::Ready(result) = first.as_mut().poll(context)
        {
            first_result = Some(result);
        }
        if second_result.is_none()
            && let Poll::Ready(result) = second.as_mut().poll(context)
        {
            second_result = Some(result);
        }
        match (first_result.as_ref(), second_result.as_ref()) {
            (Some(_), Some(_)) => Poll::Ready(
                first_result
                    .take()
                    .expect("first callback completed")
                    .and(second_result.take().expect("second callback completed")),
            ),
            _ => Poll::Pending,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    struct BarrierCallback {
        barrier: Arc<Barrier>,
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    struct CountingCallback(Arc<AtomicUsize>);

    #[async_trait]
    impl PolarWebhookCallback for CountingCallback {
        async fn call(&self, _event: &PolarWebhookEvent) -> Result<(), PolarWebhookCallbackError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl PolarWebhookCallback for BarrierCallback {
        async fn call(&self, _event: &PolarWebhookEvent) -> Result<(), PolarWebhookCallbackError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.barrier.wait().await;
            if self.fail {
                Err(PolarWebhookCallbackError::new("callback failed"))
            } else {
                Ok(())
            }
        }
    }

    fn event(event_type: PolarWebhookEventType) -> PolarWebhookEvent {
        PolarWebhookEvent {
            event_type,
            value: json!({"type": event_type.as_str(), "data": {}}),
        }
    }

    #[tokio::test]
    async fn generic_and_named_callbacks_are_polled_concurrently() {
        let barrier = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let callback = |fail| {
            Arc::new(BarrierCallback {
                barrier: barrier.clone(),
                calls: calls.clone(),
                fail,
            }) as SharedPolarWebhookCallback
        };
        let callbacks = PolarWebhookCallbacks {
            on_payload: Some(callback(false)),
            on_checkout_created: Some(callback(false)),
            ..PolarWebhookCallbacks::default()
        };
        callbacks
            .dispatch(&event(PolarWebhookEventType::CheckoutCreated))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn sdk_only_events_reach_only_on_payload_and_callback_errors_propagate() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callbacks = PolarWebhookCallbacks {
            on_payload: Some(Arc::new(BarrierCallback {
                barrier: Arc::new(Barrier::new(1)),
                calls: calls.clone(),
                fail: true,
            })),
            ..PolarWebhookCallbacks::default()
        };
        assert!(
            callbacks
                .dispatch(&event(PolarWebhookEventType::CheckoutExpired))
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn every_adapter_named_event_selects_its_callback() {
        macro_rules! assert_named {
            ($field:ident, $event:ident) => {{
                let calls = Arc::new(AtomicUsize::new(0));
                let callbacks = PolarWebhookCallbacks {
                    $field: Some(Arc::new(CountingCallback(calls.clone()))),
                    ..PolarWebhookCallbacks::default()
                };
                callbacks
                    .dispatch(&event(PolarWebhookEventType::$event))
                    .await
                    .unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 1, stringify!($event));
            }};
        }

        assert_named!(on_checkout_created, CheckoutCreated);
        assert_named!(on_checkout_updated, CheckoutUpdated);
        assert_named!(on_order_created, OrderCreated);
        assert_named!(on_order_updated, OrderUpdated);
        assert_named!(on_order_paid, OrderPaid);
        assert_named!(on_order_refunded, OrderRefunded);
        assert_named!(on_refund_created, RefundCreated);
        assert_named!(on_refund_updated, RefundUpdated);
        assert_named!(on_subscription_created, SubscriptionCreated);
        assert_named!(on_subscription_updated, SubscriptionUpdated);
        assert_named!(on_subscription_active, SubscriptionActive);
        assert_named!(on_subscription_canceled, SubscriptionCanceled);
        assert_named!(on_subscription_uncanceled, SubscriptionUncanceled);
        assert_named!(on_subscription_revoked, SubscriptionRevoked);
        assert_named!(on_product_created, ProductCreated);
        assert_named!(on_product_updated, ProductUpdated);
        assert_named!(on_organization_updated, OrganizationUpdated);
        assert_named!(on_benefit_created, BenefitCreated);
        assert_named!(on_benefit_updated, BenefitUpdated);
        assert_named!(on_benefit_grant_created, BenefitGrantCreated);
        assert_named!(on_benefit_grant_updated, BenefitGrantUpdated);
        assert_named!(on_benefit_grant_revoked, BenefitGrantRevoked);
        assert_named!(on_customer_created, CustomerCreated);
        assert_named!(on_customer_updated, CustomerUpdated);
        assert_named!(on_customer_deleted, CustomerDeleted);
        assert_named!(on_customer_state_changed, CustomerStateChanged);
    }

    #[tokio::test]
    async fn every_sdk_only_event_skips_named_callbacks() {
        let named_calls = Arc::new(AtomicUsize::new(0));
        let payload_calls = Arc::new(AtomicUsize::new(0));
        let named = Arc::new(CountingCallback(named_calls.clone())) as SharedPolarWebhookCallback;
        let callbacks = PolarWebhookCallbacks {
            on_payload: Some(Arc::new(CountingCallback(payload_calls.clone()))),
            on_checkout_created: Some(named.clone()),
            on_checkout_updated: Some(named.clone()),
            on_order_created: Some(named.clone()),
            on_order_updated: Some(named.clone()),
            on_order_paid: Some(named.clone()),
            on_order_refunded: Some(named.clone()),
            on_refund_created: Some(named.clone()),
            on_refund_updated: Some(named.clone()),
            on_subscription_created: Some(named.clone()),
            on_subscription_updated: Some(named.clone()),
            on_subscription_active: Some(named.clone()),
            on_subscription_canceled: Some(named.clone()),
            on_subscription_uncanceled: Some(named.clone()),
            on_subscription_revoked: Some(named.clone()),
            on_product_created: Some(named.clone()),
            on_product_updated: Some(named.clone()),
            on_organization_updated: Some(named.clone()),
            on_benefit_created: Some(named.clone()),
            on_benefit_updated: Some(named.clone()),
            on_benefit_grant_created: Some(named.clone()),
            on_benefit_grant_updated: Some(named.clone()),
            on_benefit_grant_revoked: Some(named.clone()),
            on_customer_created: Some(named.clone()),
            on_customer_updated: Some(named.clone()),
            on_customer_deleted: Some(named.clone()),
            on_customer_state_changed: Some(named),
        };
        let sdk_only = [
            PolarWebhookEventType::CheckoutExpired,
            PolarWebhookEventType::SubscriptionPastDue,
            PolarWebhookEventType::BenefitGrantCycled,
            PolarWebhookEventType::CustomerSeatAssigned,
            PolarWebhookEventType::CustomerSeatClaimed,
            PolarWebhookEventType::CustomerSeatRevoked,
            PolarWebhookEventType::MemberCreated,
            PolarWebhookEventType::MemberUpdated,
            PolarWebhookEventType::MemberDeleted,
        ];
        for event_type in sdk_only {
            callbacks.dispatch(&event(event_type)).await.unwrap();
        }
        assert_eq!(named_calls.load(Ordering::SeqCst), 0);
        assert_eq!(payload_calls.load(Ordering::SeqCst), sdk_only.len());
    }
}
