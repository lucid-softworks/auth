use super::{BillingInterval, Subscription, SubscriptionStatus};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StripeStoreError {
    #[error("Stripe subscription id already exists")]
    DuplicateId,
    #[error("Stripe subscription store is unavailable: {0}")]
    Unavailable(String),
}

/// A Better Auth adapter-style subscription mutation.
///
/// Nested options distinguish an omitted field from explicitly clearing a
/// nullable field, which webhook/cancel/restore transitions require.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SubscriptionPatch {
    pub plan: Option<String>,
    pub stripe_customer_id: Option<Option<String>>,
    pub stripe_subscription_id: Option<Option<String>>,
    pub status: Option<SubscriptionStatus>,
    pub period_start: Option<Option<DateTime<Utc>>>,
    pub period_end: Option<Option<DateTime<Utc>>>,
    pub trial_start: Option<Option<DateTime<Utc>>>,
    pub trial_end: Option<Option<DateTime<Utc>>>,
    pub cancel_at_period_end: Option<bool>,
    pub cancel_at: Option<Option<DateTime<Utc>>>,
    pub canceled_at: Option<Option<DateTime<Utc>>>,
    pub ended_at: Option<Option<DateTime<Utc>>>,
    pub seats: Option<Option<f64>>,
    pub billing_interval: Option<Option<BillingInterval>>,
    pub stripe_schedule_id: Option<Option<String>>,
}

impl SubscriptionPatch {
    pub fn apply(self, subscription: &mut Subscription) {
        if let Some(value) = self.plan {
            subscription.plan = value;
        }
        apply_nullable(
            self.stripe_customer_id,
            &mut subscription.stripe_customer_id,
        );
        apply_nullable(
            self.stripe_subscription_id,
            &mut subscription.stripe_subscription_id,
        );
        if let Some(value) = self.status {
            subscription.status = value;
        }
        apply_nullable(self.period_start, &mut subscription.period_start);
        apply_nullable(self.period_end, &mut subscription.period_end);
        apply_nullable(self.trial_start, &mut subscription.trial_start);
        apply_nullable(self.trial_end, &mut subscription.trial_end);
        if let Some(value) = self.cancel_at_period_end {
            subscription.cancel_at_period_end = value;
        }
        apply_nullable(self.cancel_at, &mut subscription.cancel_at);
        apply_nullable(self.canceled_at, &mut subscription.canceled_at);
        apply_nullable(self.ended_at, &mut subscription.ended_at);
        apply_nullable(self.seats, &mut subscription.seats);
        apply_nullable(self.billing_interval, &mut subscription.billing_interval);
        apply_nullable(
            self.stripe_schedule_id,
            &mut subscription.stripe_schedule_id,
        );
    }
}

fn apply_nullable<T>(patch: Option<Option<T>>, target: &mut Option<T>) {
    if let Some(value) = patch {
        *target = value;
    }
}

#[async_trait]
pub trait StripeStore: Send + Sync {
    async fn user_customer_id(&self, user_id: &str) -> Result<Option<String>, StripeStoreError>;

    async fn set_user_customer_id(
        &self,
        user_id: &str,
        customer_id: Option<String>,
    ) -> Result<(), StripeStoreError>;

    async fn user_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<String>, StripeStoreError>;

    async fn organization_customer_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<String>, StripeStoreError>;

    async fn set_organization_customer_id(
        &self,
        organization_id: Uuid,
        customer_id: Option<String>,
    ) -> Result<(), StripeStoreError>;

    async fn organization_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, StripeStoreError>;

    async fn create_subscription(
        &self,
        subscription: Subscription,
    ) -> Result<Subscription, StripeStoreError>;

    async fn find_subscription(&self, id: Uuid) -> Result<Option<Subscription>, StripeStoreError>;

    async fn find_subscription_by_stripe_id(
        &self,
        stripe_subscription_id: &str,
    ) -> Result<Option<Subscription>, StripeStoreError>;

    /// Adapter-order rows for a reference. `referenceId` is deliberately not unique.
    async fn list_subscriptions(
        &self,
        reference_id: &str,
    ) -> Result<Vec<Subscription>, StripeStoreError>;

    /// Adapter-order rows linked to a Stripe customer, including inactive rows.
    async fn list_subscriptions_by_customer(
        &self,
        stripe_customer_id: &str,
    ) -> Result<Vec<Subscription>, StripeStoreError>;

    async fn find_active_subscription_by_customer(
        &self,
        stripe_customer_id: &str,
    ) -> Result<Option<Subscription>, StripeStoreError>;

    async fn update_subscription(
        &self,
        id: Uuid,
        patch: SubscriptionPatch,
    ) -> Result<Option<Subscription>, StripeStoreError>;

    async fn delete_subscription(&self, id: Uuid)
    -> Result<Option<Subscription>, StripeStoreError>;
}
